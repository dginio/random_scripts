#!/usr/bin/env python
#coding:utf-8
import urllib,urllib2,pyglet,sys
opener = urllib2.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0')]

mp3file = opener.open("http://translate.google.com/translate_tts?tl=fr&"+urllib.urlencode({'q':sys.argv[1]}))
output = open('1.mp3','wb')
output.write(mp3file.read())
output.close()

def exit_callback(dt):
	pyglet.app.exit()

sound = pyglet.media.load('1.mp3')
sound.play()
pyglet.clock.schedule_once(exit_callback, sound.duration)
pyglet.app.run()
