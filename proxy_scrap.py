import requests
from lxml.html import fromstring
from bs4 import BeautifulSoup
from user_agent import generate_user_agent
import json
import urllib.request
import socket
import asyncio
import aiohttp
import threading
from proxy_checking import ProxyChecker

socket.setdefaulttimeout(3)
proxies = set()

url_json = ['https://github.com/fate0/proxylist/blob/master/proxy.list']
url_list = ['https://github.com/ShiftyTR/Proxy-List/blob/master/https.txt',
            'https://github.com/mmpx12/proxy-list/blob/master/https.txt',
            'https://github.com/IshanSingla/proxy-list/blob/main/proxys/https.txt',
            'https://github.com/TheSpeedX/PROXY-List/blob/master/http.txt',
            'https://github.com/RX4096/proxy-list/blob/main/online/https.txt',
            'https://github.com/HyperBeats/proxy-list/blob/main/http.txt',
            'https://github.com/mertguvencli/http-proxy-list/blob/main/proxy-list/data.txt',
            'https://github.com/ObcbO/getproxy/blob/master/https.txt',
            'https://github.com/jetkai/proxy-list/blob/main/online-proxies/txt/proxies-https.txt',
            'https://github.com/clarketm/proxy-list/blob/master/proxy-list-raw.txt',
            'https://github.com/sunny9577/proxy-scraper/blob/master/proxies.txt',
            'https://github.com/almroot/proxylist/blob/master/list.txt',
            'https://github.com/roosterkid/openproxylist/blob/main/HTTPS_RAW.txt']
url_special = ['https://github.com/UptimerBot/proxy-list/blob/main/proxies_geolocation_anonymous/http.txt']

#####################################################################################
#proxy decoder from spys.one
#####################################################################################
def conv(n, radix):
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    r = ""
    if n == 0:
        r = '0'
    else:
        while (n > 0):
            k = n % radix  # очередная цифра
            r = digits[k] + r  # приклеим к результату
            n = n // radix
    return r.lower()


def decrypt(p='', r=60, o=60, x='', y=0, s={}):
    # for spy
    def y(c):
        s = '' if c < r else y(int(c / r))
        s += chr(c % r + 29) if c % r > 35 else conv(c % r, 36)
        return s

    if True:
        while o != 0:
            o -= 1
            s[y(o)] = x[o] or y(o)
        arg_str = p.replace('^', '').replace(';', '').replace('=', '')
        x = [s[i] for i in arg_str]

        k = -1
        replaced_p = ''
        for i in p:
            if i != '=' and i != '^' and i != ';':
                k += 1
                replaced_p += x[k]
            else:
                replaced_p += i
        list_p = replaced_p[0:len(replaced_p) - 1].split(';')
        encrypt = {}
        for i in list_p:
            x = i.split('=')
            encrypt[x[0]] = x[1]
        return encrypt


def encrypt_port_part(dict_p, part):
    numbers = []

    def strTOint(element):
        try:
            int_p = element.split('^')
        except:
            int_p = element
        try:
            return int(int_p[0]) ^ int(int_p[1])
        except IndexError:
            return int(int_p[0])

    try:
        if type(int(dict_p[part][0])) == int:
            numbers.append(strTOint(dict_p[part]))
    except ValueError:
        try:
            spl_p = dict_p[part].split('^')
            for i in spl_p:
                try:
                    numbers.append(int(dict_p[i]))
                except:
                    if len(dict_p[i].split('^')) == 2:
                        strTOint(dict_p[i])
                        numbers.append(strTOint(dict_p[i]))
        except KeyError:
            numbers.append(strTOint(dict_p[part]))

    return strTOint(numbers)
#####################################################################################

def is_bad_proxy(pip, url):
    """ Thanks sudhanshu456"""
    try:
        proxy_handler = urllib.request.ProxyHandler({'https': pip})
        opener = urllib.request.build_opener(proxy_handler)
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        urllib.request.install_opener(opener)
        sock = urllib.request.urlopen(url)
    except urllib.error.HTTPError as e:
        # print('Error code: ', e.code)
        return e.code
    except Exception as detail:
        # print("ERROR:", detail)
        return 1
    return 0


async def scrapProxy_git_json(url, proxies):
    async with aiohttp.ClientSession() as session:
        headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
        response = await session.get(url, headers=headers)
        soup = BeautifulSoup(await response.text(), 'lxml')
        lines = soup.find('table',
                          class_='highlight tab-size js-file-line-container js-code-nav-container js-tagsearch-file').find_all(
            'tr')
        for string in lines:
            strip = json.loads(string.find_all('td')[1].text)
            if strip['anonymity'] != 'transparent':
                if strip['type'] != 'http':
                    if strip['country'] != 'RU':
                        try:
                            proxies.add(":".join([str(strip["host"]), str(strip["port"])]))
                        except KeyError:
                            pass


async def scrapProxy_git_list(url, proxies):
    async with aiohttp.ClientSession() as session:
        headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
        response = await session.get(url, headers=headers)
        soup = BeautifulSoup(await response.text(), 'lxml')
        lines = soup.find('table',
                          class_='highlight tab-size js-file-line-container js-code-nav-container js-tagsearch-file').find_all(
            'tr')
        for string in lines:
            strip = string.find_all('td')[1].text.replace('https://', '').replace('\r', '').split(':')
            try:
                proxies.add(":".join([str(strip[0]), str(strip[1])]))
            except IndexError:
                pass


async def scrapProxy_git_special(url, proxies):
    async with aiohttp.ClientSession() as session:
        headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
        response = await session.get(url, headers=headers)
        soup = BeautifulSoup(await response.text(), 'lxml')
        lines = soup.find('table',
                          class_='highlight tab-size js-file-line-container js-code-nav-container js-tagsearch-file').find_all(
            'tr')
        for string in lines:
            strip = string.find_all('td')[1].text.split('::')[0].replace('\r', '').split(':')
            try:
                proxies.add(":".join([str(strip[0]), str(strip[1])]))
            except IndexError:
                pass


async def scrap_FREE_proxy(proxies):
    urls = ['https://free-proxy-list.net/',
            'https://us-proxy.org/',
            'https://sslproxies.org/',
            'https://free-proxy-list.net/uk-proxy.html',
            'https://free-proxy-list.net/anonymous-proxy.html']

    async with aiohttp.ClientSession() as session:
        for url in urls:
            headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
            response = await session.get(url, headers=headers)
            parser = fromstring(str(await response.text()))
            for i in parser.xpath('//tbody/tr')[:25]:
                if i.xpath('.//td[7][contains(text(),"yes")]'):
                    proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
                    proxies.add(proxy)


async def scrap_SPY_proxy(proxies):
    url = 'https://spys.one/en/https-ssl-proxy/'

    async with aiohttp.ClientSession() as session:
        headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
        response = await session.get(url, headers=headers)
        soup = BeautifulSoup(await response.text(), 'lxml')
        script = fromstring(str(await response.text())).xpath('//body/script[1]/text()')[0]
        args = script.split('(')[23].replace('.split', '').replace("'", '').split(',')
        p = args[0]
        x = args[3].split('^')
        lines = soup.find_all('tr', class_='spy1xx')
        list2 = soup.find_all('tr', class_='spy1x')
        lines.extend(list2[1:len(list2)])
        for line in lines:
            for content in line.find_all('font'):
                ip = content.getText()
                port_cry = content.find('script').getText().split('+')
                port_math = port_cry[1:len(port_cry)]
                p_a = []
                for part_port in port_math:
                    part = part_port.replace('(', '').replace(')', '').split('^')
                    p_a.append(
                        encrypt_port_part(decrypt(p=p, x=x), part[0]) ^ encrypt_port_part(decrypt(p=p, x=x), part[1]))
                port = ''.join([str(i) for i in p_a])
                proxies.add(ip + ":" + port)
                break


async def scrap_proxy_list(proxies):
    url = 'https://www.proxy-list.download/api/v1/get?type=https'

    async with aiohttp.ClientSession() as session:
        headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
        response = await session.get(url, headers=headers)
        soup = BeautifulSoup(await response.text(), 'lxml')
        lines = soup.find('p').getText().split('\r\n')
        for line in lines[0:len(lines) - 1]:
            proxies.add(line)


async def scrap_proxyspace_list(proxies):
    url = 'https://proxyspace.pro/https.txt'

    async with aiohttp.ClientSession() as session:
        headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
        response = await session.get(url, headers=headers)
        soup = BeautifulSoup(await response.text(), 'lxml')
        lines = soup.find('p').getText().split('\n')
        for line in lines[0:len(lines) - 1]:
            proxies.add(line)


async def scrap_htmlweb(proxies):
    '''don`t working'''
    url = 'https://htmlweb.ru/analiz/proxy_list.php?type%5B0%5D=1&perpage=20&p=1'

    async with aiohttp.ClientSession() as session:
        headers = {'user-agent': generate_user_agent(os=('mac', 'linux'))}
        response = await session.get(url, headers=headers)
        soup = BeautifulSoup(await response.text(), 'lxml')
        content = soup.find('table', class_="tbl").find_all('tr')
        for i in range(1, len(content), 2):
            print(content[i].find('td').getText())


async def main():
    for url in url_json:
        await scrapProxy_git_json(url, proxies)

    for url in url_list:
        await scrapProxy_git_list(url, proxies)

    for url in url_special:
        await scrapProxy_git_special(url, proxies)

    await scrap_FREE_proxy(proxies)

    try:
        await scrap_SPY_proxy(proxies)
    except:
        print('SPY error')

    await scrap_proxy_list(proxies)

    await scrap_proxyspace_list(proxies)

    proxyList = list(proxies)

    return proxyList


def ce(item):
    """
    Here you can put the desired url.
    """
    url = 'https://www.instagram.com/'
    if not is_bad_proxy(item, url):
        good.append(item)


asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
proxyList = asyncio.run(main())

good = []
task = []
for item in proxyList:
    processor = threading.Thread(target=ce, args=(item,))
    processor.start()
    task.append(processor)
for runner in task:
    runner.join()


def get_info_proxy(checked, valid_proxies):
    checker = ProxyChecker()
    proxy_info = checker.check_proxy(checked)
    if proxy_info['status']:
        if proxy_info['anonymity'] != 'Transparent':
            try:
                if proxy_info['country'] != 'Russia':
                    if round(float(proxy_info['time_response'])) <= 2:
                        proxy_info['proxy'] = checked
                        valid_proxies.append(proxy_info)
            except KeyError:
                if round(float(proxy_info['time_response'])) <= 2:
                    proxy_info['proxy'] = checked
                    valid_proxies.append(proxy_info)


task.clear()
valid_proxies = []

for checked in good:
    processor = threading.Thread(target=get_info_proxy, args=(checked, valid_proxies, ))
    processor.start()
    task.append(processor)
for runner in task:
    runner.join()

print(valid_proxies)