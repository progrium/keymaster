from google.appengine.ext.webapp import util
from google.appengine.ext import webapp
from google.appengine.api import users
from google.appengine.ext.webapp import template
from google.appengine.ext import db
from google.appengine.api import mail
from google.appengine.api import urlfetch
from Crypto.Cipher import DES
import hashlib, time, urllib

def baseN(num,b=36,numerals="0123456789abcdefghijklmnopqrstuvwxyz"): 
    return ((num == 0) and  "0" ) or (baseN(num // b, b).lstrip("0") + numerals[num % b])

class Key(db.Model):
    user = db.UserProperty(auto_current_user_add=True)
    name = db.StringProperty(required=True)
    hash = db.StringProperty()
    callback_url = db.StringProperty(required=True)
    encrypted_data = db.BlobProperty(required=True)
    padding = db.StringProperty(required=True)
    
    created = db.DateTimeProperty(auto_now_add=True)
    updated = db.DateTimeProperty(auto_now=True)

    def __init__(self, *args, **kwargs):
        kwargs['hash'] = kwargs.get('hash', hashlib.md5(kwargs['name']+str(time.time())).hexdigest())
        super(Key, self).__init__(*args, **kwargs)

    def __str__(self):
        return "http://www.thekeymaster.org/%s" % self.hash

class MainHandler(webapp.RequestHandler):
    def get(self):
        user = users.get_current_user()
        if user:
            logout_url = users.create_logout_url("/")
            keys = Key.all().filter('user =', user)
        else:
            login_url = users.create_login_url('/')
        self.response.out.write(template.render('main.html', locals()))
    
    def post(self):
        if self.request.POST.get('hash', None):
            k = Key.all().filter('hash =', self.request.POST['hash']).get()
            k.delete()
        else:
            user = users.get_current_user()
            secret = baseN(abs(hash("GATEKEEPER" + str(time.time()))))[0:8]
            o = DES.new(secret, DES.MODE_ECB)
            data = self.request.POST['data']
            padding = '^' * (8-(len(data)%8))
            mail.send_mail(sender="The Keymaster <%s>" % user.email(),
                          to=user.email(),
                          #subject="Your secret for %s: %s" % (self.request.POST['name'], secret),
                          subject="Your secret for %s" % self.request.POST['name'],
                          body="""Your secret is:\n\n%s""" % secret)
            encrypted_data = o.encrypt(padding + data)
            k = Key(name=self.request.POST['name'],
                callback_url=self.request.POST['callback_url'],
                encrypted_data=encrypted_data,
                padding=padding,)
            k.put()
        self.redirect('/')

class KeyHandler(webapp.RequestHandler):
    def post(self):
        key_hash = self.request.path.split('/')[-1]
        try:
            o = DES.new(self.request.POST['secret'], DES.MODE_ECB)
            k = Key.all().filter('hash =', key_hash).get()
            key_data = o.decrypt(k.encrypted_data).replace(k.padding, '')
            resp = urlfetch.fetch(k.callback_url, payload=urllib.urlencode({'key': key_data}), method='POST', deadline=10)
            if resp.status_code >= 400:
                mail.send_mail(sender="The Keymaster <%s>" % k.user.email(),
                              to=k.user.email(),
                              subject="Failed returning %s [%s]" % (k.name, resp.status_code),
                              body=resp.content)
                self.response.set_status(502)
                self.response.out.write('Key failed to send. Error sent to key owner.')
            else:
                self.response.out.write('Key was sent')
        except KeyError:
            self.response.set_status(403)
            self.response.out.write("Secret is needed")
        except (UnicodeDecodeError, ValueError):
            self.response.set_status(403)
            self.response.out.write("Bad secret")

def main():
    application = webapp.WSGIApplication([
        ('/', MainHandler),
        ('/.*', KeyHandler),
        ], debug=True)
    util.run_wsgi_app(application)

if __name__ == '__main__':
    main()
