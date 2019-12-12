import json
import requests
from flask import Flask
from flask_pymongo import PyMongo
from flask import Flask, render_template

app = Flask(__name__)


app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb+srv://dbuser:dbuserpassword@cluster0-o5lsl.mongodb.net/test?retryWrites=true&w=majority"
mongo = PyMongo(app)

@app.route("/")
def index():
    user_collection = mongo.db.users
    user_collection.insert({'name': 'harry'})
    user_collection.insert({'name': 'jordan'})
    return '<h1> user added </h1>'



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
