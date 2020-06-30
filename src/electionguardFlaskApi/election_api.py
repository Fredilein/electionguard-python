import os

from typing import List, Dict, Optional

from electionguard.election import ElectionDescription, InternalElectionDescription, CiphertextElectionContext
from electionguard.election_builder import ElectionBuilder
from electionguard.elgamal import ElGamalKeyPair, elgamal_keypair_random, ElementModQ
from electionguard.ballot import PlaintextBallot, CiphertextBallot, PlaintextBallotContest, PlaintextBallotSelection
from electionguard.encrypt import EncryptionDevice, EncryptionMediator
from electionguard.ballot_box import BallotBox
from electionguard.ballot_store import BallotStore
from electionguard.tally import CiphertextTally, tally_ballots


class ElectionApi:
    """
    Helper class for holding a quick election. The functions mainly correspond
    to the flask_app endpoints.

    TODO: Make return values consistent, probably as JSON including a status code
    """

    metadata: InternalElectionDescription
    context: CiphertextElectionContext
    encrypter: EncryptionMediator
    store: BallotStore
    ballot_box: BallotBox
    keypair: ElGamalKeyPair
    ballots_encrypted: List[CiphertextBallot]

    def __init__(self) -> None:
        self.store = BallotStore()
        self.ballots_encrypted = []

    def create_election(self) -> str:
        """
        An election with only one guardian and random keys gets generated.
        More configuration options and the ability to hold a key ceremony should be added later.
        """
        # Open an election manifest file
        with open(os.path.join("data/election-manifest.json"), "r") as manifest:
            string_representation = manifest.read()
            election_description = ElectionDescription.from_json(string_representation)

        # Create an election builder instance, and configure it for a single public-private keypair.
        # in a real election, you would configure this for a group of guardians.  See Key Ceremony for more information.
        builder = ElectionBuilder(
            number_of_guardians=1,  # since we will generate a single public-private keypair, we set this to 1
            quorum=1,  # since we will generate a single public-private keypair, we set this to 1
            description=election_description
        )

        # We simply generate a random keypair. For a real election this step should
        # be replaced by the key ceremony
        self.keypair = elgamal_keypair_random()

        builder.set_public_key(self.keypair.public_key)

        # get an `InternalElectionDescription` and `CiphertextElectionContext`
        # that are used for the remainder of the election.
        (self.metadata, self.context) = builder.build()

        # Configure an encryption device
        # In the docs the encrypter device gets defined when encrypting a ballot.
        # I think for our usecase it makes more sense to define one encrypter and use for the whole election
        device = EncryptionDevice("polling-place-one")
        self.encrypter = EncryptionMediator(self.metadata, self.context, device)

        self.ballot_box = BallotBox(self.metadata, self.context, self.store)

        return "Election created!"

    def encrypt_ballot(self, data: dict) -> Optional[str]:
        """
        The ballot gets encrypted and stored in the ballots_encrypted field for the
        cast/spoil decision later.
        :param data: Ballot in JSON format, see data/example-ballot.json for a reference
        :return: the tracker code of the ballot
        """
        ballot: PlaintextBallot = ballot_from_json(data['ballot'])

        # Encrypt the ballot
        encrypted_ballot: CiphertextBallot = self.encrypter.encrypt(ballot)

        self.ballots_encrypted.append(encrypted_ballot)

        # TODO: Return more infos as JSON
        return encrypted_ballot.get_tracker_code()

    def cast_spoil_ballot(self, ballot_id: str, do_cast: bool) -> str:
        """
        :param ballot_id:
        :param do_cast: cast ballot if true, spoil otherwise (improvable...)
        :return: Response message string
        """
        # Search for the ballot with ballot_id in ballots_encrypted
        ballot = next((b for b in self.ballots_encrypted if b.object_id == ballot_id), None)
        if not ballot:
            return "No ballot with this ID exists"
        if do_cast:
            accepted_ballot = self.ballot_box.cast(ballot)
            res = "Ballot casted!"
        else:
            accepted_ballot = self.ballot_box.spoil(ballot)
            res = "Ballot spoiled!"
        # The ballot is both returned, and placed into the ballot store
        assert (self.store.get(accepted_ballot.object_id) == accepted_ballot)

        return res

    def tally(self) -> Dict[str, int]:
        """
        Should later be replaced with the proper tallying done by multiple trustees
        :return: Election results
        """
        tally = tally_ballots(self.store, self.metadata, self.context)
        decrypted_tallies = _decrypt_with_secret(tally, self.keypair.secret_key)

        return decrypted_tallies


def ballot_from_json(ballot: dict) -> PlaintextBallot:
    """
    Every candidate must be in the selection array right now, with the plaintext field indicating
    if voted for him or not. See data/example-ballot.json
    """
    # TODO: Ballot validation
    # TODO: Allow style of example ballots

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
    tally: CiphertextTally, secret_key: ElementModQ
) -> Dict[str, int]:
    plaintext_selections: Dict[str, int] = {}
    for _, contest in tally.cast.items():
        for object_id, selection in contest.tally_selections.items():
            plaintext = selection.message.decrypt(secret_key)
            plaintext_selections[object_id] = plaintext

    return plaintext_selections




