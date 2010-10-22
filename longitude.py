#!/usr/bin/env python

"""longitude.py: Fetch data from Google Latitude and save to sqlite db."""

import urlparse
import sys
import os.path
import datetime
import json
import sqlite3
import ConfigParser

import oauth2 as oauth

config = ConfigParser.RawConfigParser()
config.read('longitude.cfg');

scope = "https://www.googleapis.com/auth/latitude"
loc = 'https://www.googleapis.com/latitude/v1/location?granularity=best&max-results=1000'

domain = config.get('auth', 'key')
secret = config.get('auth', 'secret')

request_token_url = "https://www.google.com/accounts/OAuthGetRequestToken?scope=%s" % (scope)
authorize_url = 'https://www.google.com/latitude/apps/OAuthAuthorizeToken?domain=%s&location=all&granularity=best' % (domain)
access_token_url = 'https://www.google.com/accounts/OAuthGetAccessToken'

consumer = oauth.Consumer(domain, secret)

if not os.path.isfile('keys'):
    client = oauth.Client(consumer)

    # Get a request token.
    resp, content = client.request(request_token_url, "GET")
    if resp['status'] != '200':
        raise Exception("Invalid response %s." % resp['status'])
    request_token = dict(urlparse.parse_qsl(content))

    print "Request Token:"
    print "    - oauth_token        = %s" % request_token['oauth_token']
    print "    - oauth_token_secret = %s" % request_token['oauth_token_secret']
    print

    # Step 2: Link to web page where the user can approve the request token.
    print "Go to the following link in your browser:"
    print "%s&oauth_token=%s" % (authorize_url, request_token['oauth_token'])
    print

    raw_input('Press enter after authorizing.')

    # Step 3: Get access token using approved request token
    token = oauth.Token(request_token['oauth_token'], request_token['oauth_token_secret'])
    client = oauth.Client(consumer, token)

    resp, content = client.request(access_token_url, "POST")
    access_token = dict(urlparse.parse_qsl(content))

    print "Access Token:"
    print "    - oauth_token        = %s" % access_token['oauth_token']
    print "    - oauth_token_secret = %s" % access_token['oauth_token_secret']
    print

    # Access content using access token
    token = oauth.Token(access_token['oauth_token'], access_token['oauth_token_secret'])
    keys = open('keys', 'w')
    keys.write(access_token['oauth_token'] + "\n")
    keys.write(access_token['oauth_token_secret'])
else:
    keys = open('keys', 'r')
    oauth_token = keys.readline().strip()
    oauth_token_secret = keys.readline().strip()
    token = oauth.Token(oauth_token, oauth_token_secret)

client = oauth.Client(consumer, token)

resp, content = client.request(loc, 'GET')
if resp['status'] != '200':
    raise Exception("Invalid response %s." % resp['status'])

data = json.loads(content)

items = data['data']['items']

if(not os.path.isfile('track/loc_db')):
    conn = sqlite3.connect('track/loc_db')
    conn.execute('create table tracks_location (timestamp integer primary key, latitude real, longitude real, accuracy real)')
else:
    conn = sqlite3.connect('track/loc_db')

c = conn.cursor()

already = 0
new = 0

for item in items:
    c.execute('select * from tracks_location where timestamp=?', (long(item['timestampMs']),))
    if(c.fetchone() != None):
        already += 1
    else:
        new += 1
    vals = (long(item['timestampMs']), float(item['latitude']), float(item['longitude']), float(item['accuracy']))
    c.execute('insert or ignore into tracks_location (timestamp, latitude, longitude, accuracy) values (?, ?, ?, ?)', vals)

conn.commit()

print "Added: " + str(new) + "\nSkipped: " + str(already) + "\n"
