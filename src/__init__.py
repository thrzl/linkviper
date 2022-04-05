from typing import Optional
from cachetools import TTLCache, cached, LRUCache

from fastapi import FastAPI, HTTPException
from aiohttp import ClientSession, TCPConnector

from fastapi_utils.tasks import repeat_every

from asyncio import get_event_loop, coroutine, sleep

cache = TTLCache(ttl=900, maxsize=5)

domain_lists = [
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt",
]

sussy_domain_lists = [  # ඞ
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/suspicious-list.txt"
]

app = FastAPI()
tcpconn = TCPConnector(ttl_dns_cache=3600)
http = ClientSession(connector=tcpconn)

loop = get_event_loop()


async def refresh_cache():
    for url in domain_lists:
        res = await http.get(url)
        cache[url] = (await res.text("utf-8")).splitlines()
        await sleep(450)

@cached(cache=TTLCache(3, 450))
def get_all_links(suspicious=False):
    l = []
    for url_list in cache.keys():
        for url in cache[url_list]:
            if url not in l:
                l.append(url)
    # l = (zip([[url for url in cache[url_list]] for url_list in cache.keys()]))
    # fl = []
    # for i in l:
    #     if i not in fl:
    #         fl.append(i)
    return l

@cached(cache=TTLCache(3, 450))
def check_link(url, suspicious=False):
    return (url in get_all_links(suspicious))

@cached(cache=LRUCache(250))
def where_link(url):
    return [i for i in cache.keys() if url in cache[i]][0]


@app.on_event("startup")
@repeat_every(seconds=10)
async def startup_event():
    await refresh_cache()


@app.get("/")
async def routes():
    return app.routes


@app.get("/links/{url}")
async def read_item(url: str, suspicious: Optional[bool] = False):
    if not check_link(url, suspicious):
        raise HTTPException(status_code=404, detail="Item not found")

    
    return {
        "result": True,
        "source": [i for i in cache.keys() if url in cache[i]][0]
    }


@app.get("/links")
async def all_links(suspicious: Optional[bool] = False):
    return {"result": get_all_links(suspicious)}
