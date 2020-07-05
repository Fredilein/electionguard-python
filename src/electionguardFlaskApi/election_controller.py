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

class ElectionController:

    def __init__(self) -> None:
        print("Initialized Controller")

    def create_election(self, election_id: str) -> dict:
        election_path: str = './data/' + election_id
        if os.path.isdir(election_path):
            return {
                'success': 0,
                'msg': 'Election already exists'
            }
        os.makedirs(election_path)

        (metadata, context, encrypter, ballot_box, store, keypair) = create()
        ballots_encrypted: List = []

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
        election_path: str = './data/' + election_id
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

    def cast_spoil_ballot(self, election_id: str, data: dict, do_cast: bool) -> dict:
        election_path: str = './data/' + election_id
        ballots_encrypted = pickle.load(open(election_path + BALLOTS_ENCRYPTED, 'rb'))
        ballot_box = pickle.load(open(election_path + BALLOT_BOX, 'rb'))
        store = pickle.load(open(election_path + STORE, 'rb'))
        metadata = pickle.load(open(election_path + METADATA, 'rb'))
        context = pickle.load(open(election_path + CONTEXT, 'rb'))

        (res, store_new) = cast_spoil(data['ballotId'], do_cast, ballots_encrypted, ballot_box, store, metadata, context)
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
        election_path: str = './data/' + election_id
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
