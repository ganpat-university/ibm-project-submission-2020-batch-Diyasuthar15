from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, String
import joblib, logging as log
from os.path import sep
import pandas as pd, os

log.basicConfig(level=log.DEBUG, filemode='w', filename=f'static{sep}logs{sep}main.log',
                format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

log.info('Flask app started')

@app.route('/', methods=['GET'])
def home():
    return "Welcome to AIMA API"

@app.route('/predict/', methods=['POST'])
def predictAndSave():
    try:
        data = request.get_json()
        data = pd.read_json(data, orient='records')
        log.info('Data received successfully')
    except Exception as e:
        log.error('Error receiving data: ', exc_info=True)
        return jsonify({"message": "Error receiving data"})
    try:
        lr = joblib.load(f'.{sep}static{sep}data{sep}LogisticRegressionModel.joblib')
        dt = joblib.load(f'.{sep}static{sep}data{sep}DecisionTreeModel.joblib')
        rf = joblib.load(f'.{sep}static{sep}data{sep}RandomForestModel.joblib')
        log.info('Models loaded successfully')
    except Exception as e:
        log.error('Error loading models: ', exc_info=True)
        return jsonify({"message": "Error loading models"})
    
    try:
        data1 = data
        lr_pred = lr.predict(data1)
        dt_pred = dt.predict(data1)
        rf_pred = rf.predict(data1)
        log.info('Prediction done successfully')
    except Exception as e:
        log.error('Error predicting data: ', exc_info=True)
        return jsonify({"message": "Error predicting data"})
    
    return_data = pd.DataFrame(columns=['class_lr', 'class_dt', 'class_rf'])
    return_data.loc[0, 'class_lr'] = lr_pred[0]
    return_data.loc[0, 'class_dt'] = dt_pred[0]
    return_data.loc[0, 'class_rf'] = rf_pred[0]
    
    print(return_data, type(return_data))
    
    return jsonify({"message": "Data inserted successfully", "result": return_data.to_json(orient='records')})