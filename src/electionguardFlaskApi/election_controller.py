from typing import List
import pickle
import os

from electionguard.ballot import PlaintextBallot, CiphertextBallot
from electionguard.elgamal import elgamal_encrypt
from electionguard.elgamal import ElGamalCiphertext, ElementModQ, ElGamalKeyPair, ElementModP
from gmpy2 import mpz

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
        metadata = pickle.load(open(election_path + METADATA, 'rb'))
        context = pickle.load(open(election_path + CONTEXT, 'rb'))
        ballots_encrypted = pickle.load(open(election_path + BALLOTS_ENCRYPTED, 'rb'))

        encrypted_ballot: CiphertextBallot = encrypt_colors(data['ballot'], metadata, context)
        ballots_encrypted.append(encrypted_ballot)

        pickle.dump(ballots_encrypted, open(election_path + BALLOTS_ENCRYPTED, 'wb'))

        return {
            'success': 1,
            'msg': 'Ciphertext ballot created and stored',
            'ballotTracker': encrypted_ballot.get_tracker_code()
        }

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

    def get_publickey(self, election_id: str):
        election_path: str = self.path + election_id
        keypair = pickle.load(open(election_path + KEYPAIR, 'rb'))

        res = publickey(keypair)
        print(keypair.public_key)
        enc = elgamal_encrypt(1, ElementModQ(10), keypair.public_key)

        if res:
            return {
                'success': 1,
                'msg': 'Valid Public Key found',
                'pk': str(res),
                'enc': str(enc)
            }
        else:
            return {
                'success': 0
            }

    # TODO: Kind of important to remove later... Just for debugging encryption
    def get_secretkey(self, election_id: str):
        election_path: str = self.path + election_id
        keypair = pickle.load(open(election_path + KEYPAIR, 'rb'))

        res = secretkey(keypair)
        # dec = ElGamalCiphertext(alpha=ElementModP(elem=mpz(
        #     841249573709336292766379329403071719088336570418298708823718240422329656478770114094165163306554399028952483265202267271466007620015442790903563763690326173748454285817257276739229557098226273404257210278399347339042924346377797530512333500374445779721450152004048456200574190972737395563453412733901755327212379186767727498876159258404450323404763065237893408207296667502507939927840731105707318993246457504933315472359028489648387097524084682231623686481897395727060087498908713951994916346114885588492794940074408117919089481146283458745803829953416331970539759636592310159752110802881403031296460079558933397682677501254783193472043787195854957395581022147988630225874055000094140432707640459704823624735829161642396573466908330316843524317446917205043260218472177300317726797641981910196785687189958124251085126316681250584313417481520369664684958533587079842043689169921037733554797554818260659633169929456877110281493511688689191738672935284305397950809171660368503449527211482707034869320490336133053377642102249011728618879729399332211082815047796442793189929308022258828080072135076845281024705792191465356018862805132589256440608774401042811800243260360177723468821707354624763426987258479633666021660814173282907229885538)),
        #     beta=ElementModP(elem=mpz(
        #         650627795345403323290587654876043616186128264850139471389502213319573936584749592910235747655552942116762190722044885910191728346911990576651014566340173402174749340514055015696283529432192524879492452902212837335553473542441037311008965438426897508966973029642321643751532881988319819153864222417228633632530803733456097340806206659644425044082609386650056431842238894820875420875483728473460136101659775443336689433073508233618762006481466657245901481581359312679183196047048989501916767455556012665732253513812092223773054798979774154384855421791828470510269487169051913185750633746880388157556500194331690199313954702170729478661693732338643373589214326607069299531402940690193067370582759756383993949666929807968481240619118249704242740956793448487324557468778161606975022457625699214924069129426852723614305690284270798211401908040599493381342654595032745174759748859270807394374001118541340623491039367735440801389372383392766224257444676447392061153819924898641752042628706320320452293691167792567708260693143326532363974474377644636228665126096824464321949676436445536239809588799408407381642096378498173463011305546532766012840559131701577085278319482715443823364755975011491980219951010181856220785065009664597780569957933064875711300652462756132366432065049083076646791060574294533696748683495521458352401022498293609571605560534592605464110183685563747110512580493186253278890415107022586927122742072641081566797863292813695797227511751941602302011598121533515609218024893692536885527495498558755819665920314629936788408022598178715539530220229876905879016704272075917074920142752435139712158938852818232943295256554228205590945904948398081190783792806590440216931149492727774551913728472906739035023842517628362943564260964564483329348466794154931043454403783233806878360098081411913681557798297738723347408368337826568117121066223348228274089155395728220080570603400739194449654755779408506203161543792459074279401930500200752361421494758986490557315651921274022576700394034620711039691756744664784247378018574614215672210363914636104055568268711937593659119741093210926869743597419120850603765361102511361647885803995590431604737842642334036536065020747659385196592518221004804640902731764779562637551010120973828426094712013976156319838067553931006130546370357075186060826586215958833724182199267088134872116403811064718326102873070226958209860796967281251386487463247382782437835385572645313684905430408326929242241120310154072120793905714447774012))).decrypt(
        #     keypair.secret_key)
        dec = 'test'

        if res:
            return {
                'success': 1,
                'msg': 'Tallied ballots and decrypted result',
                'sk': str(res),
                'dec': dec
            }
        else:
            return {
                'success': 0
            }
