#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
import base64
import hashlib
import hmac
import logging
from django.utils import simplejson as json
from google.appengine.ext import webapp
from google.appengine.ext.webapp import util

APP_SECRET = ''

def base64_url_decode(data):
    data = data.encode(u'ascii')
    data += '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data)

def base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip('=')

def parse_signed_request(signed_request, secret):

    encoded_sig, payload = signed_request.split('.', 2)

    sig = base64_url_decode(encoded_sig)
    data = json.loads(base64_url_decode(payload))

    if data.get('algorithm').upper() != 'HMAC-SHA256':
        return None
    else:
        expected_sig = hmac.new(secret, msg=payload, digestmod=hashlib.sha256).digest()

    if sig != expected_sig:
        raise Exception('signature did not mismatch...possible forgery?')

    return data

class MainHandler(webapp.RequestHandler):
    def get(self):
        self.response.out.write('Welcome to Facebook API Demo!')

class CreditsHandler(webapp.RequestHandler):

    def post(self):
        data = {}
        signed_request = self.request.get('signed_request')
        request = parse_signed_request(signed_request, APP_SECRET)

        if not request:
            self.response.out.write('')

        payload = request['credits']
        logging.info('payload: %s' % payload)

        method = self.request.get('method')
        order_id = payload['order_id']

        if method == 'payments_status_update':
            data['content'] = {}
            status = payload['status']

            if status == 'placed':
                order_details = json.loads(payload['order_details'])
                #save order details into database
                data['content']['status'] = 'settled'
            elif status == 'settled':
                order_details = json.loads(payload['order_details'])
                buyer = order_details['buyer']
                item = order_details['items'][0]
                #modify order status into database
            else:
                data['content']['status'] = status

            data['content']['order_id'] = order_id

        elif method == 'payments_get_items':
            items = []
            item = {}
            order_info = json.loads(payload['order_info'])
            if not order_info or not isinstance(order_info, dict):
                item['title'] = 'Facebook Credits Demo'
                item['price'] = 1
                item['description'] = 'This is a Facebook Credits Demo ...'
                item['image_url'] = 'http://www.facebook.com/images/gifts/21.png'
                item['product_url'] = 'http://www.facebook.com/images/gifts/21.png'
                items.append(item)
                logging.info('item: %s' % item)
            else:
                items.append(order_info)
                logging.info('item: %s' % order_info)

            data['content'] = items

        data['method'] = method

        logging.info(json.dumps(data))
        self.response.out.write(json.dumps(data))

    def get(self):
        pass


def main():
    application = webapp.WSGIApplication([('/', MainHandler),
                                         ('/callback/', CreditsHandler)],
                                         debug=True)
    util.run_wsgi_app(application)


if __name__ == '__main__':
    main()
