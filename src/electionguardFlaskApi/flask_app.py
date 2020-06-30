from flask import Flask, request, jsonify, Response, json
from flask_cors import CORS

from electionguardFlaskApi.election_api import ElectionApi

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'


election: ElectionApi = ElectionApi()


@app.route('/')
def hello_world():
    return '<h1>ElectionGuard Python Flask API</h1>'


@app.route('/electionguard/CreateElection')
def request_create_election():
    return election.create_election()


@app.route('/electionguard/EncryptBallot', methods=['POST'])
def request_encrypt_ballot():
    data = request.json
    return jsonify(election.encrypt_ballot(data))


@app.route('/electionguard/CastBallot/<ballot_id>')
def request_cast_ballot(ballot_id):
    return election.cast_spoil_ballot(ballot_id, do_cast=True)


@app.route('/electionguard/SpoilBallot/<ballot_id>')
def request_spoil_ballot(ballot_id):
    return election.cast_spoil_ballot(ballot_id, do_cast=False)


@app.route('/electionguard/Tally')
def request_tally():
    return election.tally()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
