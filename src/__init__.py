from typing import Optional
from cachetools import TTLCache, cached, LRUCache
from progress.bar import ChargingBar
from progress.spinner import PixelSpinner

from fastapi import FastAPI, HTTPException
from aiohttp import ClientSession, TCPConnector
from time import sleep as syncs

from fastapi_utils.tasks import repeat_every

from asyncio import get_event_loop, coroutine, sleep

cache = TTLCache(ttl=900, maxsize=5)

domain_lists = [
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt",
    "https://hole.cert.pl/domains/domains.txt"
]

sussy_domain_lists = [  # ඞ
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/suspicious-list.txt"
]

app = FastAPI()

# ? uncomment for profiling
# from fastapi_profiler.profiler_middleware import PyInstrumentProfilerMiddleware
# app.add_middleware(PyInstrumentProfilerMiddleware)

tcpconn = TCPConnector(ttl_dns_cache=3600)
http = ClientSession(connector=tcpconn)

domain_count = 0

loop = get_event_loop()


async def refresh_cache():
    with ChargingBar("downloading domain lists", max=len(domain_lists)) as bar:
        for url in domain_lists:
            res = await http.get(url)
            cache[url] = (await res.text("utf-8")).splitlines()
            bar.next()
        bar.finish()

def cache_all():
    urls = get_all_links(suspicious=True)
    with ChargingBar("caching list", max=(51282)) as bar: # 62000 is the approx. link count
        for index, url in enumerate(urls):
            # print(check_link(url))
            if check_link(url): where_link(url)
            if index % 1000 == 0: bar.message=url; bar.next(1000)
        bar.finish()

@cached(cache=TTLCache(500, 450))
def get_all_links(suspicious=False, task=False) -> list:
        l = []
        # with ChargingBar("processing domains", max=51282) as bar:
        for url_list in cache.keys():
            for index, url in enumerate(cache[url_list]):
                if url not in l:
                    l.append(url)
                    # if index % 100 == 0: bar.next(100)
        # bar.finish()
        # return list({url for url in cache[url_list] for url_list in cache.keys()})
        return l


@cached(cache=TTLCache(500, 450))
def check_link(url, suspicious=False):
    return url in get_all_links(suspicious)


@cached(cache=LRUCache(250))
def where_link(url):
    return [i for i in cache.keys() if url in cache[i]][0]


@app.on_event("startup")
@repeat_every(seconds=3600)  # 1h
async def startup_event():
    await sleep(1) # stuff gets garbled after a while
    await refresh_cache()
    cache_all()
    print(f"ready with {len(get_all_links())} domains!")


@app.get("/")
async def routes():
    return "alive!"


@app.get("/links/{url}")
async def read_item(url: str, suspicious: Optional[bool] = False):
    if not check_link(url, suspicious):
        raise HTTPException(status_code=404, detail="Item not found")

    return {"result": True, "source": where_link(url)}


@app.get("/links")
async def all_links(suspicious: Optional[bool] = False):
    all_domains = get_all_links(suspicious)
    return {"result": all_domains, "totalAmount": len(all_domains), "sources": domain_lists}
