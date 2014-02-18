#!/bin/env python

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import os
import torndb
import bcrypt
import tornado_flash

from tornado.options import define, options

define("port", default=8889, help="run on the given port", type=int)
define("mysql_host", default="127.0.0.1:3306", help="blog database host")
define("mysql_database", default="blog", help="blog database name")
define("mysql_user", default="blog", help="blog database user")
define("mysql_password", default="blog", help="blog database password")

class Application(tornado.web.Application):
  def __init__(self):
    handlers = [
        (r"/", MainHandler),
        (r"/login", LoginHandler),
        (r"/reg", RegisterHandler),
        (r"/logout", LogoutHandler),
        (r"/testflash", TestFlashHandler),
        (r"/test_auth", TestAuthHandler),
        (r".*", PageNotFoundHandler),
    ]
    settings = dict(
        title = "tornado blog app",
        template_path=os.path.join(os.path.dirname(__file__), "templates"),
        static_path=os.path.join(os.path.dirname(__file__), "static"),
        xsrf_cookies=True,
        debug=True,
        login_url="/login",
        cookie_secret="4C2I8ieSSWyqJjs59dXlhLjosev9Ikxbvj3nxMZzxMI="
    )
    tornado.web.Application.__init__(self, handlers, **settings)
    # Have one global connection to the blog DB across all handlers
    self.db = torndb.Connection(
        host=options.mysql_host, database=options.mysql_database,
        user=options.mysql_user, password=options.mysql_password)

class BaseHandler(tornado.web.RequestHandler):
  def write_error(self, status_code, **kwargs):
    if status_code == 500:
      self.render('html/500.html', error_code=500,
                  error_message='Internal Error!')
    elif status_code == 404:
      self.render('html/404.html', error_code=404,
                  error_message='Page Not Found!')
    else:
      super(BaseHandler, self).write_error(status_code, **kwargs)

  # the property decoder copy application db to handler, needed it,
  # or it may not find db connection in handler
  @property
  def db(self):
    return self.application.db

  def get_current_user(self):
    user_id = self.get_secure_cookie("bloguser")
    if not user_id: return None
    return self.db.get("SELECT * FROM authors WHERE id = %s", int(user_id))

class PageNotFoundHandler(BaseHandler):
  def get(self):
    raise tornado.web.HTTPError(404)

class MainHandler(BaseHandler):
  def get(self):
    flash = tornado_flash.Flash(self)
    self.render("index.html", flash=flash)

class TestFlashHandler(BaseHandler):
  def get(self):
    flash = tornado_flash.Flash(self)
    #flash.data = {"class": "warning", "msg": "WARNING!"}
    flash.set_data("data", {"class": "warning", "msg": "WARNING!!!!!!"})
    self.render("index.html", flash=flash)

class TestAuthHandler(BaseHandler):
  @tornado.web.authenticated
  def get(self):
    self.render("test_auth.html")

class LoginHandler(BaseHandler):
  @tornado.web.asynchronous
  def get(self):
    self.render("login.html")

  def post(self):
    username = self.get_argument("username")
    password = self.get_argument("password")
    author = self.db.get("SELECT * from authors where name = '%s'" % str(username))

    if not author:
      pass
    # password_digest must be str, may it may raise error
    if bcrypt.hashpw(password.encode('utf-8'), str(author.password_digest)) == str(author.password_digest):
      self.set_secure_cookie("bloguser", str(author.id))
      self.redirect(self.get_argument("next", "/"))
    else:
      self.redirect("/")
      return

class LogoutHandler(BaseHandler):
  def get(self):
    self.clear_cookie("bloguser")
    self.redirect(self.get_argument("next", "/"))

class RegisterHandler(BaseHandler):
  def get(self):
    self.render("reg.html")

  def post(self):
    id = self.get_argument("id", None)
    username=self.get_argument("username")
    password=self.get_argument("password")
    password_confirm = self.get_argument("password-repeat")
    if password != password_confirm:
      self.redirect("/reg")
      return
    self.write("user(%s) password(%s)register ok" %(username, password))
    password_digest = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(12))
    id = self.db.execute(
        "INSERT INTO authors (name, password_digest, email) values (%s, %s, '   ')",
        username, password_digest)
    self.set_secure_cookie("bloguser", str(id))
    self.redirect(self.get_argument("next", "/"))


def main():
  tornado.options.parse_command_line()
  http_server = tornado.httpserver.HTTPServer(Application())
  http_server.listen(options.port)
  tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
  main()

