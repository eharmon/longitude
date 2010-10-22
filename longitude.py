#!/usr/bin/env python

"""longitude.py: Fetch data from Google Latitude and save to sqlite db."""

import urlparse
import sys
import os.path
import datetime
import json
import sqlite3
import ConfigParser
import argparse

import oauth2 as oauth

parser = argparse.ArgumentParser(description='Fetch data from Google Latitude')
parser.add_argument('--config', '-c', metavar='file', nargs='?', type=argparse.FileType('r'), default='longitude.cfg', dest='config_file', help='longitude configuration file')
parser.add_argument('--keys', '-k',  metavar='file', nargs='?', type=argparse.FileType('r+'), default='keys', dest='keys_file', help='oauth key storage file')
parser.add_argument('--db', '-d', metavar='file', nargs='?', type=str, default='loc_db', dest='db_file', help='sqlite storage DB for storing waypoints')
parser.add_argument('-v', action='store_true', dest='verbose', help='be verbose')
args = parser.parse_args()

config = ConfigParser.RawConfigParser()
config.readfp(args.config_file);

scope = "https://www.googleapis.com/auth/latitude"
loc = 'https://www.googleapis.com/latitude/v1/location?granularity=best&max-results=1000'

domain = config.get('auth', 'key')
secret = config.get('auth', 'secret')

request_token_url = "https://www.google.com/accounts/OAuthGetRequestToken?scope=%s" % (scope)
authorize_url = 'https://www.google.com/latitude/apps/OAuthAuthorizeToken?domain=%s&location=all&granularity=best' % (domain)
access_token_url = 'https://www.google.com/accounts/OAuthGetAccessToken'

consumer = oauth.Consumer(domain, secret)

oauth_token = args.keys_file.readline().strip()
oauth_token_secret = args.keys_file.readline().strip()
token = oauth.Token(oauth_token, oauth_token_secret)
if(not oauth_token or not oauth_token_secret):
    client = oauth.Client(consumer)

    print "Keys file is empty or corrupted, getting new authorization credentials..."

    # Get a request token.
    resp, content = client.request(request_token_url, "GET")
    if resp['status'] != '200':
        raise Exception("Invalid response %s." % resp['status'])
    request_token = dict(urlparse.parse_qsl(content))

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

    # Access content using access token
    token = oauth.Token(access_token['oauth_token'], access_token['oauth_token_secret'])
    args.keys_file.write(access_token['oauth_token'] + "\n")
    args.keys_file.write(access_token['oauth_token_secret'])

    print "Authentication complete, starting initial import..."
    args.verbose = True

client = oauth.Client(consumer, token)

resp, content = client.request(loc, 'GET')
if resp['status'] != '200':
    raise Exception("Invalid response %s." % resp['status'])

data = json.loads(content)

items = data['data']['items']

if(not os.path.isfile(args.db_file)):
    conn = sqlite3.connect(args.db_file)
    conn.execute('create table tracks_location (timestamp integer primary key, latitude real, longitude real, accuracy real)')
else:
    conn = sqlite3.connect(args.db_file)
    try:
        conn.execute('select * from tracks_location limit 1')
    except sqlite3.OperationalError:
        raise Exception('Unable to read from database, possible corruption?')

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

if(args.verbose):
    print "Import results:"
    print "\tAdded: " + str(new) + "\n\tSkipped: " + str(already)
