import os
import json

from typing import List, Dict, Optional, Tuple
from secrets import randbelow
from gmpy2 import mpz

from electionguard.election import ElectionDescription, InternalElectionDescription, CiphertextElectionContext
from electionguard.election_builder import ElectionBuilder
from electionguard.elgamal import ElGamalKeyPair, elgamal_keypair_random, ElementModQ, ElGamalCiphertext, elgamal_add
from electionguard.ballot import PlaintextBallot, CiphertextBallot, CiphertextBallotContest, CiphertextBallotSelection, PlaintextBallotContest, \
    PlaintextBallotSelection
from electionguard.encrypt import EncryptionDevice, EncryptionMediator, contest_from
from electionguard.ballot_box import BallotBox, accept_ballot, BallotBoxState
from electionguard.ballot_store import BallotStore
from electionguard.tally import CiphertextTally, tally_ballots
from electionguard.hash import hash_elems
from electionguard.nonces import Nonces
from electionguard.utils import get_optional, get_or_else_optional_func
from electionguard.group import Q, ElementModP, ElementModQ, int_to_q_unchecked
from electionguard.logs import log_warning

"""
Helper functions for holding a quick election. The functions mainly correspond
to the flask_app endpoints.
"""

# TODO: Allow clients to provide election-manifest.json
ELECTION_MANIFEST = "data/election-manifest.json"


def create() -> Tuple:
    """
    An election with only one guardian and random keys gets generated.
    More configuration options and the ability to hold a key ceremony should be added later.
    """
    # Open an election manifest file
    with open(os.path.join(ELECTION_MANIFEST), "r") as manifest:
        string_representation = manifest.read()
        election_description = ElectionDescription.from_json(string_representation)

    # Create an election builder instance, and configure it for a single public-private keypair.
    # in a real election, you would configure this for a group of guardians.  See Key Ceremony for more information.
    # TODO: Allow real key ceremony
    builder = ElectionBuilder(
        number_of_guardians=1,  # since we will generate a single public-private keypair, we set this to 1
        quorum=1,  # since we will generate a single public-private keypair, we set this to 1
        description=election_description
    )

    # We simply generate a random keypair. For a real election this step should
    # be replaced by the key ceremony
    keypair = elgamal_keypair_random()

    builder.set_public_key(keypair.public_key)

    # get an `InternalElectionDescription` and `CiphertextElectionContext`
    # that are used for the remainder of the election.
    (metadata, context) = builder.build()

    # Configure an encryption device
    # In the docs the encrypter device gets defined when encrypting a ballot.
    # I think for our usecase it makes more sense to define one encrypter and use for the whole election
    device = EncryptionDevice("polling-place-one")
    encrypter = EncryptionMediator(metadata, context, device)

    store = BallotStore()
    ballot_box = BallotBox(metadata, context, store)

    return metadata, context, encrypter, ballot_box, store, keypair


def encrypt(ballot_as_dict: dict, encrypter: EncryptionMediator) -> CiphertextBallot:
    """
    The ballot gets encrypted and stored in the ballots_encrypted field for the
    cast/spoil decision later.
    :param encrypter:
    :param ballot_as_dict:
    :return:
    """
    ballot: PlaintextBallot = ballot_from_json(ballot_as_dict)

    # Encrypt the ballot
    encrypted_ballot: CiphertextBallot = encrypter.encrypt(ballot)

    return encrypted_ballot


def encrypt_colors(ballot_as_dict: dict, election_metadata: InternalElectionDescription,
                             context: CiphertextElectionContext) -> CiphertextBallot:
    # Generate a random master nonce to use for the contest and selection nonce's on the ballot
    # Optional, maybe later.
    random_master_nonce = get_or_else_optional_func(
        None, lambda: int_to_q_unchecked(randbelow(Q))
    )

    # Include a representation of the election and the external Id in the nonce's used
    # to derive other nonce values on the ballot
    nonce_seed = hash_elems(
        context.crypto_extended_base_hash, ballot_as_dict['objectId'], random_master_nonce,
    )

    encrypted_contests: List[CiphertextBallotContest] = list()

    for contest_description in election_metadata.get_contests_for(ballot_as_dict['ballotStyle']):
        use_contest = None
        for contest in ballot_as_dict['contests']:
            if contest['objectId'] == contest_description.object_id:
                use_contest = contest
                break
        # no selections provided for the contest, so create a placeholder contest
        if not use_contest:
            print('no contest')
            break

        contest_description_hash = contest_description.crypto_hash()
        nonce_sequence = Nonces(contest_description_hash, nonce_seed)
        chaum_pedersen_nonce = next(iter(nonce_sequence))

        # Encrypt Selections
        encrypted_selections: List[CiphertextBallotSelection] = list()

        for selection_description in contest_description.ballot_selections:
            for selection in use_contest['ballotSelections']:
                if selection['objectId'] == selection_description.object_id:
                    # encrypted_selection = encrypt_selection(
                    #     selection, description, elgamal_public_key, contest_nonce
                    # )
                    selection_description_hash = selection_description.crypto_hash()
                    nonce_sequence = Nonces(selection_description_hash, nonce_seed)
                    selection_nonce = nonce_sequence[selection_description.sequence_order]
                    disjunctive_chaum_pedersen_nonce = next(iter(nonce_sequence))

                    elgamal_encryption = ElGamalCiphertext(ElementModP(mpz(int(selection['ciphertext']['a']))), ElementModP(mpz(int(selection['ciphertext']['b']))))

                    encrypted_selection = CiphertextBallotSelection(
                        object_id=selection['objectId'],
                        description_hash=selection_description_hash,
                        message=elgamal_encryption,
                        elgamal_public_key=context.elgamal_public_key,
                        proof_seed=disjunctive_chaum_pedersen_nonce,
                        nonce=selection_nonce,
                        selection_representation=0,
                    )
                    break

            if encrypted_selection is None:
                print('no encrypted selection')
                break  # log will have happened earlier
            encrypted_selections.append(encrypted_selection)

        # Encrypt Contest
        encrypted_contest = CiphertextBallotContest(
            object_id=use_contest['objectId'],
            description_hash=contest_description_hash,
            ballot_selections=encrypted_selections,
            elgamal_public_key=context.elgamal_public_key,
            proof_seed=chaum_pedersen_nonce,
            number_elected=contest_description.number_elected,
        )

        if encrypted_contest is None:
            print('no encrypted contest')
            break  # log will have happened earlier
        encrypted_contests.append(encrypted_contest)

    encrypted_ballot = CiphertextBallot(
        ballot_as_dict['objectId'],
        ballot_as_dict['ballotStyle'],
        context.crypto_extended_base_hash,
        encrypted_contests,
    )

    # should use seed_hash instead of nonce_seed
    encrypted_ballot.generate_tracking_id(nonce_seed)

    return encrypted_ballot


def cast_spoil(ballot_id: str, do_cast: bool, ballots_encrypted: List, store: BallotStore,
               metadata: InternalElectionDescription, context: CiphertextElectionContext) -> (bool, BallotStore):
    """
    :param context:
    :param metadata:
    :param store:
    :param ballots_encrypted:
    :param ballot_id:
    :param do_cast: cast ballot if true, spoil otherwise (could be cleaner...)
    :return: Status code and the new store. store gets modified in accept_ballot without being explicitly returned
    """
    # Search for the ballot with ballot_id in ballots_encrypted
    ballot = next((b for b in ballots_encrypted if b.object_id == int(ballot_id)), None)
    if not ballot:
        print('not ballot')
        return False, store
    if do_cast:
        accepted_ballot = accept_ballot(ballot, BallotBoxState.CAST, metadata, context, store)
        assert (store.get(accepted_ballot.object_id) == accepted_ballot)
        return True, store
    else:
        accepted_ballot = accept_ballot(ballot, BallotBoxState.SPOILED, metadata, context, store)
        assert (store.get(accepted_ballot.object_id) == accepted_ballot)
        return True, store


def tally(store: BallotStore, metadata: InternalElectionDescription, context: CiphertextElectionContext,
          keypair: ElGamalKeyPair) -> Dict[str, int]:
    """
    Should later be replaced with the proper tallying done by multiple trustees
    :return: Election results
    """

    validateBallots(store, keypair)

    tally = tally_ballots(store, metadata, context)
    decrypted_tallies = _decrypt_with_secret(tally, keypair.secret_key)

    return decrypted_tallies


def validateBallots(store: BallotStore, keypair: ElGamalKeyPair):
    for ballot in store:
        if ballot.state != BallotBoxState.CAST:
            continue
        # iterate through the contests and elgamal add
        for contest in ballot.contests:

            messages: [ElGamalCiphertext] = []
            for selection in contest.ballot_selections:
                messages.append(selection.message)

            acc: ElGamalCiphertext = elgamal_add(*messages)
            print('decryption')
            selection_sum = acc.decrypt(keypair.secret_key)

            if selection_sum > 1:
                log_warning(
                    f"ballot {ballot.object_id} has a value greater than one for some candidates"
                )
                return False

    return True


def publickey(keypair: ElGamalKeyPair) -> int:
    return keypair.public_key.to_int()


def ballot_from_json(ballot: dict) -> PlaintextBallot:
    # TODO: Ballot validation

    voted_contests: List[PlaintextBallotContest] = []
    for contest in ballot['contests']:
        voted_selections: List[PlaintextBallotSelection] = []

        for selection in contest['ballotSelections']:
            voted_selections.append(
                PlaintextBallotSelection(
                    selection['objectId'],
                    plaintext=selection['plaintext'],
                    is_placeholder_selection=False,
                )
            )

        voted_contests.append(
            PlaintextBallotContest(contest['objectId'], voted_selections)
        )

    return PlaintextBallot(ballot['objectId'], ballot['ballotStyle'], voted_contests)


def _decrypt_with_secret(
        ciphertext_tally: CiphertextTally, secret_key: ElementModQ
) -> Dict[str, int]:
    plaintext_selections: Dict[str, int] = {}
    for _, contest in ciphertext_tally.cast.items():
        for object_id, selection in contest.tally_selections.items():
            plaintext = selection.message.decrypt(secret_key)
            plaintext_selections[object_id] = plaintext

    return plaintext_selections
