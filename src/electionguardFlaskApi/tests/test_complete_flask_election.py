import unittest
import json
import shutil
import os

from electionguardFlaskApi.flask_app import app

"""
The whole election gets tested in one test case because we don't want to tear down everything after each step of
the election. It would be nicer to test each step separately though.

A data directory is created in the tests folder and the election-manifest.json file is copied to this folder. If the
election-manifest is changed the create_ballot function needs to be changed as well. After the test everything created
is automatically deleted.

Pickle throws a lot of ResourceWarnings when executing the test. We call pickle.dump(... open(file)) and thus never 
close the file manually. Change that in the future!
"""


class CompleteFlaskElectionTest(unittest.TestCase):

    def setUp(self) -> None:
        self.app = app.test_client()
        os.mkdir('./data')
        shutil.copy('../data/election-manifest.json', './data/election-manifest.json')

    def testElection(self) -> None:
        # Create Election
        response = self.app.get('/test/CreateElection')
        print(response.json)
        self.assertEqual(1, response.json['success'])

        # Encrypt two ballots
        payload = create_ballot("ballot-id-1")
        response = self.app.post('/test/EncryptBallot', headers={"Content-Type": "application/json"}, data=payload)
        self.assertEqual(1, response.json['success'])
        payload = create_ballot("ballot-id-2")
        response = self.app.post('/test/EncryptBallot', headers={"Content-Type": "application/json"}, data=payload)
        self.assertEqual(1, response.json['success'])

        # Cast Ballot
        payload = json.dumps({
            "ballotId": "ballot-id-1"
        })
        response = self.app.post('/test/CastBallot', headers={"Content-Type": "application/json"}, data=payload)
        self.assertEqual(1, response.json['success'])

        # Spoil Ballot
        payload = json.dumps({
            "ballotId": "ballot-id-2"
        })
        response = self.app.post('/test/SpoilBallot', headers={"Content-Type": "application/json"}, data=payload)
        self.assertEqual(1, response.json['success'])

        # Tally
        response = self.app.get('/test/Tally')
        self.assertEqual(1, response.json['success'])
        self.assertEqual(1, response.json['decryptedTally']['guido-selection'])
        self.assertEqual(1, response.json['decryptedTally']['referendum-pineapple-negative-selection'])
        # Maybe test 0-values as well

    def tearDown(self) -> None:
        shutil.rmtree('./data')


def create_ballot(ballot_id: str):
    return json.dumps({
        "ballot": {
            "objectId": ballot_id,
            "ballotStyle": "example-county-ballot-style",
            "contests": [
                {
                    "objectId": "president-eth",
                    "ballotSelections": [
                        {
                            "objectId": "turing-selection",
                            "plaintext": "False"
                        },
                        {
                            "objectId": "torvalds-selection",
                            "plaintext": "False"
                        },
                        {
                            "objectId": "guido-selection",
                            "plaintext": "True"
                        }
                    ]
                },
                {
                    "objectId": "referendum-pineapple",
                    "ballotSelections": [
                        {
                            "objectId": "referendum-pineapple-affirmative-selection",
                            "plaintext": "False"
                        },
                        {
                            "objectId": "referendum-pineapple-negative-selection",
                            "plaintext": "True"
                        }
                    ]
                }
            ]
        }
    })
