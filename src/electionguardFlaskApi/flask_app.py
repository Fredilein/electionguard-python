from flask import Flask, request, jsonify, Response, json
from flask_cors import CORS

from electionguardFlaskApi.election_controller import ElectionController

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

electionController: ElectionController = ElectionController('./data/')

"""
When calling the tally endpoint, this whole script gets executed 10 times in approximately one second...
electionController gets constructed each time, verifiable by inserting a print statement here.
I have no idea why.
"""

@app.route('/')
def hello_world():
    return '<h1>Electionguard Python Flask API</h1>'


@app.route('/<election_id>/CreateElection')
def request_create_election(election_id):
    return jsonify(electionController.create_election(election_id))


@app.route('/<election_id>/EncryptBallot', methods=['POST'])
def request_encrypt_ballot(election_id):
    data = request.json
    return jsonify(electionController.encrypt_ballot(election_id, data))


@app.route('/<election_id>/CastBallot', methods=['POST'])
def request_cast_ballot(election_id):
    data = request.json
    return jsonify(electionController.cast_spoil_ballot(election_id, data, do_cast=True))


@app.route('/<election_id>/SpoilBallot', methods=['POST'])
def request_spoil_ballot(election_id):
    data = request.json
    return jsonify(electionController.cast_spoil_ballot(election_id, data, do_cast=False))


@app.route('/<election_id>/Tally')
def request_tally(election_id):
    return jsonify(electionController.create_tally(election_id))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
