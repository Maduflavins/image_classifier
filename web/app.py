from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://127.0.0.1:27017")
db  = client.ImageRecognition
users = db["Users"]
admin = db["admin"]


def UserExist(username):
    if users.count_documents({"Username":username})==0:
        return False
    else:
        return True

def verifyPassword(username, password):
    if not UserExist:
        return False
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw)==hashed_pw:
        return True
    else:
        return False


def generateReturnDictionary(status, message):
    retJson = {
        "status": status,
        "message": message
    }
    return retJson

def verifyCredentials(username, password):
    if not UserExist(username):
        return generateReturnDictionary(301, "Invalid Username"), True

        correct_pw = verifyPassword(username, password)
        if not correct_pw:
            return generateReturnDictionary(302, "Invalid Password"), True

    return None, False


def adminExist(username):
    if admin.count_documents({"Username":username})==0:
        return False
    else:
        return True

def verifyAdminPassword(username, password):
    if not adminExist:
        return False
    hashed_pw = admin.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw)==hashed_pw:
        return True
    return False




class RegisterAdmin(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["admin_pw"]

        if UserExist(username):
            return jsonify(generateReturnDictionary(301, "user already exist"))
        
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        admin.insert({
            "Username": username,
            "password": hashed_pw
        })




class Register(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        if UserExist(username):
            retJson = {
                "status code": 301,
                "message": "There is an already registered user"
            }
            return jsonify(retJson)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())


        users.insert({
            "Username": username,
            "Password": hashed_pw,
            "Tokens": 7

        })

        retJson = {
            "status code": 200,
            "message": "You successfully signed up for this API"
        }
        return jsonify(retJson)


class Classify(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        url = postedData["url"]


        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        tokens = users.find({
            "Username": username
        })[0]["Tokens"]

        if tokens <= 0:
            return jsonify(generateReturnDictionary(303, "Not enough Tokens"))

        
        r = requests.get(url)
        retJson = {}
        with open("temp.jpg", "wb") as f:
            f.write(r.content)
            proc = subprocess.Popen('python classifier.py --model_dir=. --image_file=./temp.jpg')
            proc.communicate()[0]
            proc.wait()
            with open("text.txt") as g:
                retJson = json.load(g)
            
        users.update({
            "Username": username
        }, {
            "$set": {
                "Tokens": tokens - 1
            }
        })
        return retJson




class Refill(resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["admin_pw"]
        amount = postedData["amount"]


        if not adminExist(username):
            return jsonify(generateReturnDictionary(301, "Invalid Username"))
        
        correct_pw = verifyAdminPassword(username, password)

        if not correct_pw:
            return jsonify(generateReturnDictionary(304, "Invalid admin password"))

        users.update({
            "Username": username
        },{
            "$set": {
                "Tokens": amount
            }
        })

        return jsonify(generateReturnDictionary(200, "Refilled Successfully"))



api.add_resource(RegisterAdmin, '/admin')
api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')


if __name__=='__main__':
    app.run(host='0.0.0.0')