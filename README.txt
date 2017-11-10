The CookieEncryptionService has been implemented as a part of protection mechanism
from DDoS attacks. The idea behind it is the following: generate & encrypt cookie, using
ipAddress & browserId as key, and then check presence of the cookie along with Requests
for particular URLs.