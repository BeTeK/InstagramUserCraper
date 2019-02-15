import sys
import urllib.parse
import urllib.request

import requests
from constants import *
import json
import time
import config

class Main:
  def __init__(self, user, passwd, queryHash):
    self.session = requests.Session()
    self.session.headers = {'user-agent': CHROME_WIN_UA}
    self.session.cookies.set('ig_pr', '1')
    self.rhx_gis = None
    self.queryHash = queryHash
    
    self.cookies = None
    self.logged_in = False
    self.login_user = user
    self.login_pass = passwd
    self.quit = False

  def getUserById(self, userId):
    queryHash = self.queryHash
    variables = '{"user_id":"' + userId + '","include_chaining":false,"include_reel":true,"include_suggested_users":false,"include_logged_out_extras":false,"include_highlight_reels":false}'
    
    qdata = {"query_hash" : queryHash,
             "variables": variables}
    encodedData = urllib.parse.urlencode(qdata)
    resp = self.session.get("https://www.instagram.com/graphql/query/?" + encodedData, data=qdata)

    try:
      return json.loads(resp.text)
    except:
      sys.stderr.write(str(resp.text))
      sys.stderr.flush()
      return None
    
  def login(self):
    """Logs in to instagram."""
    self.session.headers.update({'Referer': BASE_URL, 'user-agent': STORIES_UA})
    req = self.session.get(BASE_URL)
    
    self.session.headers.update({'X-CSRFToken': req.cookies['csrftoken']})
    
    login_data = {'username': self.login_user, 'password': self.login_pass}
    login = self.session.post(LOGIN_URL, data=login_data, allow_redirects=True)
    self.session.headers.update({'X-CSRFToken': login.cookies['csrftoken']})
    self.cookies = login.cookies
    login_text = json.loads(login.text)
    
    if login_text.get('authenticated') and login.status_code == 200:
      self.logged_in = True
      self.session.headers = {'user-agent': CHROME_WIN_UA}
      self.rhx_gis = self.get_shared_data()['rhx_gis']

  def get_shared_data(self, username=''):
    """Fetches the user's metadata."""
    resp = self.get_json(BASE_URL + username)
    
    if resp is not None and '_sharedData' in resp:
      try:
        shared_data = resp.split("window._sharedData = ")[1].split(";</script>")[0]
        return json.loads(shared_data)
      except (TypeError, KeyError, IndexError):
        pass

  def get_json(self, *args, **kwargs):
    """Retrieve text from url. Return text as string or None if no data present """
    resp = self.safe_get(*args, **kwargs)
    
    if resp is not None:
      return resp.text
    
  def safe_get(self, *args, **kwargs):
      # out of the box solution
      # session.mount('https://', HTTPAdapter(max_retries=...))
      # only covers failed DNS lookups, socket connections and connection timeouts
      # It doesnt work when server terminate connection while response is downloaded
      retry = 0
      retry_delay = RETRY_DELAY
      while True:
          if self.quit:
              return
          try:
              response = self.session.get(timeout=CONNECT_TIMEOUT, cookies=self.cookies, *args, **kwargs)
              if response.status_code == 404:
                  return
              response.raise_for_status()
              content_length = response.headers.get('Content-Length')
              if content_length is not None and len(response.content) != int(content_length):
                  #if content_length is None we repeat anyway to get size and be confident
                  raise Exception('Partial response')
              return response
          except (KeyboardInterrupt):
              raise
          except (requests.exceptions.RequestException, PartialContentException) as e:
              if 'url' in kwargs:
                  url = kwargs['url']
              elif len(args) > 0:
                  url = args[0]
              if retry < MAX_RETRIES:
                  self.logger.warning('Retry after exception {0} on {1}'.format(repr(e), url))
                  self.sleep(retry_delay)
                  retry_delay = min( 2 * retry_delay, MAX_RETRY_DELAY )
                  retry = retry + 1
                  continue
              else:
                  keep_trying = self._retry_prompt(url, repr(e))
                  if keep_trying == True:
                      retry = 0
                      continue
                  elif keep_trying == False:
                      return
              raise
              
def loadUserData(data):
  pass
#  url = "https://www.instagram.com/graphql/query/?{0}".format(data)
#  data = None
#  with urllib.request.urlopen(url) as f:
#    data = f.read()
#
#  print(data)
  
def main():
  data = urllib.parse.urlencode({"query_hash" : queryHash,
                                 "variables": '{"user_id":"206356827","include_chaining":true,"include_reel":true,"include_suggested_users":false,"include_logged_out_extras":false,"include_highlight_reels":true}'})
  insta = Main(config.username, config.password, config.queryHash)
  insta.login()
  count = 0

  allUserIds = set()
  with open(sys.argv[1], "rb") as f:
    for userIdRaw in f:
      userId = userIdRaw.decode("UTF-8").replace("\n", "").replace("\r", "").replace(" ", "")
      if userId != "":
        allUserIds.add(userId)

  loadedIds = set()
  with open(sys.argv[2], "rb") as f:
    for userIdRaw in f:
      userId = userIdRaw.decode("UTF-8").replace("\n", "").replace("\r", "").replace(" ", "")
      idNamePair = userId.split(";")
      if len(idNamePair) != 2:
        sys.stderr.write("fail {0}\n".format(userId))
        sys.stderr.flush()
        
        return
      loadedIds.add(idNamePair[0])
      
  toBeLoaded = allUserIds - loadedIds

  for userId in toBeLoaded:
    while True:
      try:
        userReel = insta.getUserById(userId)

        if userReel is None or ("status" in userReel and userReel["status"] == "fail"):
          sys.stderr.write(str(userReel) + "\n")
          printProgress(len(loadedIds) + count, len(allUserIds))
          time.sleep(60)
          continue

        if userReel["data"]["user"] is None:
          break
      
        reelId = userReel["data"]["user"]["reel"]["user"]["id"]
        reelUsername = userReel["data"]["user"]["reel"]["user"]["username"]
        print("{0};{1}".format(reelId, reelUsername))
      
        if count % 1000 == 0:
          printProgress(len(loadedIds) + count, len(allUserIds))
        
        count += 1
        break
      
      except Exception as ex:
        sys.stderr.write(str(userReel) + "\n")
        sys.stderr.flush()
        raise ex

def printProgress(count, allCount):
  sys.stderr.write("progress {0}/{1}\n".format(count, allCount))
  sys.stderr.flush()
  
if __name__ == "__main__":
    main()
