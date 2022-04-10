from cachetools import TTLCache, cached, LFUCache
from progress.bar import ChargingBar
from redis import from_url, Redis
from os import environ
from brotli_asgi import BrotliMiddleware

r: Redis =  from_url(
    url=environ["REDIS_URL"],
    )


from fastapi import FastAPI, HTTPException, Response
from aiohttp import ClientSession, TCPConnector

from fastapi_utils.tasks import repeat_every

cache: TTLCache = TTLCache(ttl=900, maxsize=5)

domain_lists = [
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt",
    "https://hole.cert.pl/domains/domains.txt"
]

sussy_domain_lists = [  # ඞ
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/suspicious-list.txt"
]

app = FastAPI()

app.add_middleware(BrotliMiddleware, minimum_size=1000)

# ? uncomment for profiling
# from fastapi_profiler.profiler_middleware import PyInstrumentProfilerMiddleware
# app.add_middleware(PyInstrumentProfilerMiddleware)

tcpconn = TCPConnector(ttl_dns_cache=3600)
http = ClientSession(connector=tcpconn)

domain_count = 0

async def refresh_cache() -> dict:
    with ChargingBar("downloading domain lists", max=len(domain_lists)) as bar:
        all_domains = {}
        for url in domain_lists:
            res = await http.get(url)
            all_domains[url] = (await res.text("utf-8")).splitlines()
            bar.next()
        bar.finish()
    return all_domains

def cache_all(domains: dict):
    pipe = r.pipeline()
    with ChargingBar("caching list", max=(61634)) as bar: # 62000 is the approx. link count
        for url_list in domains.keys():
            for index, url in enumerate(domains[url_list]):
                pipe.setnx(url, url_list)
                if index % 10 == 0: bar.next(10)
        pipe.execute()
        bar.finish()

@cached(cache=TTLCache(500, 450))
def get_all_links(suspicious=False) -> list:
    return r.keys()

@app.on_event("startup")
@repeat_every(seconds=3600)  # 1h
async def startup_event():
    print(f"ready with {len(get_all_links())} domains!")

async def refresh_stuff():
    domains = await refresh_cache()
    cache_all(domains)

@cached(cache=LFUCache(maxsize=50))
def check_link(url):
    return r.get(url)

@app.get("/")
async def routes():
    return "alive!"


@app.get("/links/{url}")
async def read_item(url: str, response: Response):
    if not (source := check_link(url)):
        response.status_code = 404
        raise HTTPException(status_code=404, detail="Item not found")
    return {"result": True, "source": source}


@app.get("/links")
async def all_links():
    all_domains = get_all_links()
    return {"result": all_domains, "totalAmount": r.dbsize(), "sources": domain_lists}
