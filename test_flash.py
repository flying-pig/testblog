#!/bin/env python

import tornado_flash
import tornado.web

flash = tornado_flash.Flash(tornado.web.RequestHandler)
print flash
