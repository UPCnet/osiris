import unittest
import os

from pyramid import testing
from paste.deploy import loadapp

from osiris.appconst import ACCESS_TOKEN_LENGTH


class osirisTests(unittest.TestCase):
    def setUp(self):
        conf_dir = os.path.dirname(__file__)
        self.app = loadapp('config:test.ini', relative_to=conf_dir)
        from webtest import TestApp
        self.testapp = TestApp(self.app)

    def tearDown(self):
        self.app.registry.osiris_store._conn.drop_collection(self.app.registry.settings.get('osiris.store.collection'))
        testing.tearDown()

    def test_token_endpoint(self):
        # Allow pass the arguments via standard post payload
        payload = {"grant_type": "password", "username": "testuser", "password": "test", 'client_id': 'MAX'}
        resp = self.testapp.post('/token', payload, status=200)
        response = resp.json
        self.assertTrue('oauth_token' in response and len(response.get('oauth_token')) == ACCESS_TOKEN_LENGTH)
        self.assertTrue('scope' in response and response.get('scope') is None)
        self.assertTrue('fresh' in response)
        self.assertFalse('token_type' in response)
        self.assertFalse('expires_in' in response)
        self.assertEqual(resp.content_type, 'application/json')

    def test_check_token_endpoint(self):
        payload = {"grant_type": "password", "username": "testuser", "password": "test", 'client_id': 'MAX'}
        resp = self.testapp.post('/token', payload, status=200)
        oauth_token = resp.json.get('oauth_token')

        # POST payload
        payload = {"oauth_token": str(oauth_token), "user_id": "testuser", "grant_type": "password"}
        resp = self.testapp.post('/checktoken', payload, status=200)