from typing import List
import pickle
import os

from electionguard.ballot import PlaintextBallot, CiphertextBallot

from electionguardFlaskApi.election import *

# Define filenames for data storage
METADATA = '/metadata.obj'
CONTEXT = '/context.obj'
ENCRYPTER = '/encrypter.obj'
BALLOT_BOX = '/ballot_box.obj'
STORE = '/store.obj'
BALLOTS_ENCRYPTED = '/ballots_encrypted.obj'
KEYPAIR = '/keypair.obj'

"""
ElectionController mainly handles loading and storing of data and then calling the desired function in election.py
with this data.

I don't know if it makes sense to make ElectionController a class.
I did it this way to make it more obvious that the flask app only calls functions from the controller.
"""

class ElectionController:

    # Path where all the election data gets stored. Default: ./data/
    path: str

    def __init__(self, path: str) -> None:
        self.path = path
        print("Initialized Controller")

    def create_election(self, election_id: str) -> dict:
        election_path: str = self.path + election_id
        if os.path.isdir(election_path):
            return {
                'success': 0,
                'msg': 'Election already exists'
            }
        os.makedirs(election_path)

        (metadata, context, encrypter, ballot_box, store, keypair) = create()
        ballots_encrypted: List = []

        # TODO: Close opened files... Maybe automate storing things with pickle
        pickle.dump(metadata, open(election_path + METADATA, 'wb'))
        pickle.dump(context, open(election_path + CONTEXT, 'wb'))
        pickle.dump(encrypter, open(election_path + ENCRYPTER, 'wb'))
        pickle.dump(ballot_box, open(election_path + BALLOT_BOX, 'wb'))
        pickle.dump(store, open(election_path + STORE, 'wb'))
        pickle.dump(ballots_encrypted, open(election_path + BALLOTS_ENCRYPTED, 'wb'))
        pickle.dump(keypair, open(election_path + KEYPAIR, 'wb'))

        return {
            'success': 1,
            'msg': 'Election created'
        }

    def encrypt_ballot(self, election_id: str, data: dict) -> dict:
        election_path: str = self.path + election_id
        encrypter = pickle.load(open(election_path + ENCRYPTER, 'rb'))
        ballots_encrypted = pickle.load(open(election_path + BALLOTS_ENCRYPTED, 'rb'))

        encrypted_ballot: CiphertextBallot = encrypt(data['ballot'], encrypter)
        ballots_encrypted.append(encrypted_ballot)

        pickle.dump(ballots_encrypted, open(election_path + BALLOTS_ENCRYPTED, 'wb'))

        return {
            'success': 1,
            'msg': 'Ballot was encrypted and stored',
            'ballotTracker': encrypted_ballot.get_tracker_code()
        }

    def encrypt_ballot_colors(self, election_id: str, data: dict) -> dict:
        election_path: str = self.path + election_id
        encrypter = pickle.load(open(election_path + ENCRYPTER, 'rb'))
        ballots_encrypted = pickle.load(open(election_path + BALLOTS_ENCRYPTED, 'rb'))

    def cast_spoil_ballot(self, election_id: str, data: dict, do_cast: bool) -> dict:
        election_path: str = self.path + election_id
        ballots_encrypted = pickle.load(open(election_path + BALLOTS_ENCRYPTED, 'rb'))
        ballot_box = pickle.load(open(election_path + BALLOT_BOX, 'rb'))
        store = pickle.load(open(election_path + STORE, 'rb'))
        metadata = pickle.load(open(election_path + METADATA, 'rb'))
        context = pickle.load(open(election_path + CONTEXT, 'rb'))

        print(len(ballots_encrypted))

        (res, store_new) = cast_spoil(data['ballotId'], do_cast, ballots_encrypted, store, metadata, context)

        pickle.dump(store_new, open(election_path + STORE, 'wb'))

        msg_end = 'cast' if do_cast else 'spoiled'
        if res:
            return {
                'success': 1,
                'msg': f'Ballot successfully {msg_end}'
            }
        else:
            return {
                'success': 0,
                'msg': f'Ballot could not be {msg_end}'
            }

    def create_tally(self, election_id: str):
        election_path: str = self.path + election_id
        store = pickle.load(open(election_path + STORE, 'rb'))
        metadata = pickle.load(open(election_path + METADATA, 'rb'))
        context = pickle.load(open(election_path + CONTEXT, 'rb'))
        keypair = pickle.load(open(election_path + KEYPAIR, 'rb'))

        res = tally(store, metadata, context, keypair)

        if res:
            return {
                'success': 1,
                'msg': 'Tallied ballots and decrypted result',
                'decryptedTally': res
            }
        else:
            return {
                'success': 0
            }

    def list_elections(self):
        base_dir = self.path
        elections = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]

        if elections:
            return {
                'success': 1,
                'msg': f'{len(elections)} elections found',
                'elections': elections
            }
        else:
            return {
                'success': 0,
                'msg': 'No elections found'
            }