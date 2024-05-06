from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

import pandas as pd, os, re,requests, asyncio, logging as log
from aima.settings import BASE_DIR
from asgiref.sync import sync_to_async
from .models import PermissionCount

def preprocessAPK(apkPath: str, data, feature_df):
    # print('apkPath:',apkPath)
    try:
        name = apkPath.split('\\')[-1]
    except:
        name = apkPath.split('/')[-1]
    columns = ["fileName"]
    
    for col in data.columns:
        columns.append(col)
    
    # print(columns)
    # columns.remove("class")
    columns+=["class_lr", "class_dt", "class_rf"]
    test_df = pd.DataFrame(columns=columns)
    # test_df.head(10)
    
    permissions_list = feature_df[feature_df["Category"] == "Manifest Permission"].X.unique()
    api_call_signatures = feature_df[feature_df["Category"] == "API call signature"].X.unique()
    intents = feature_df[feature_df["Category"] == "Intent"].X.unique()
    keywords = feature_df[feature_df["Category"] == "Commands signature"].X.unique()
    
    index=0
    test_df.loc[index, "fileName"] = name
    test_df
    
    a = APK(apkPath)
    d = DalvikVMFormat(a.get_dex())
    
    permissions = a.get_permissions()
    manifest = a.get_android_manifest_xml()
    intent_filters = manifest.findall(".//intent-filter")
    
    found_permissions = []
    found_api_signatures = []
    found_intents = []
    found_keywords = []
    
    for permission in permissions:
        permission = permission.split(".")[-1]
        if permission in permissions_list:
            found_permissions.append(permission)
    
    for permission in permissions_list:
        if permission in found_permissions:
            test_df[permission] = 1
        else:
            test_df[permission] = 0
    
    for method in d.get_methods():
        for api_call in api_call_signatures:
            if re.search(api_call.encode('utf-8'), method.get_descriptor()):
                found_api_signatures.append(api_call)
    
    for api_call in api_call_signatures:
        if api_call in found_api_signatures:
            test_df[api_call] = 1
        else:
            test_df[api_call] = 0
    
    for intent_filter in intent_filters:
        action_elements = intent_filter.findall(".//action")
        for action_element in action_elements:
            action_value = action_element.get("{http://schemas.android.com/apk/res/android}name")
            for intent in intents:
                if re.search(intent, action_value):
                    found_intents.append(intent)
    
    for intent in intents:
        if intent in found_intents:
            test_df[intent] = 1
        else:
            test_df[intent] = 0
    
    for method in d.get_methods():
        for keyword in keywords:
            try:
                if re.search(keyword, method.get_code().get_instruction()):
                    found_keywords.append(keyword)
            except:
                pass
    
    for keyword in keywords:
        if keyword in found_keywords:
            test_df[keyword] = 1
        else:
            test_df[keyword] = 0
    
    fileName = test_df.loc[index, "fileName"]
    dropped = test_df.drop(["fileName","class_lr","class_dt","class_rf"], axis=1)
    return dropped, fileName

def getFeatureDF():
    from scipy.stats import chi2_contingency
    data = pd.read_csv(f'{BASE_DIR}{os.path.sep}static{os.path.sep}data{os.path.sep}malware-benign.csv', encoding="utf-8", low_memory=False, na_values="?")
    input_columns = data.columns[:-1]
    output_column = data.columns[-1]

    contingency_table = pd.crosstab(data[input_columns[0]], data[output_column])

    chi2_p={}
    for column in input_columns:
        contingency_table = pd.crosstab(data[column], data[output_column])
        chi2, p, _, _ = chi2_contingency(contingency_table)
        chi2_p[column] = (chi2, p)

    new_chi2_p = {key: val for key, val in chi2_p.items() if val[1] < 0.05}

    chi2_vals = [val[0] for val in new_chi2_p.values()]

    chi2_vals.sort(reverse=True)

    final_chi2_p = {key: val for key, val in new_chi2_p.items() if val[0] > 675}

    imp_cols=list(final_chi2_p.keys())
    imp_cols+=['class']

    feature_df = pd.read_csv(f'{BASE_DIR}{os.path.sep}static{os.path.sep}data{os.path.sep}features.csv', header=None, names=["X", "Category"])

    feature_df=feature_df[feature_df['X'].isin(imp_cols)]  # only keep the important features
    
    data=data.filter(feature_df['X'].tolist())
    
    return data,feature_df

class verifyApp:

    def initDataBase(self):
        self.data1, self.feature_df = getFeatureDF()

    def verifyAppIfMallicious(self,apkPath: str):
        self.data, self.fileName = preprocessAPK(apkPath, self.data1, self.feature_df)

    def getFinalResult(self):
        print('data:\n', self.data)
        # data = self.data.drop(['class_rf', 'class_dt', 'class_lr'], axis=1)
        
        # print(data.values)
        
        data_json = self.data.to_json(orient='records')
        # https://ars0206.pythonanywhere.com/predict
        response = requests.post('http://localhost:5000/predict/', json=data_json)
        print('response code',response.status_code)
        # print(response.json())
        
        if response.status_code == 200:
            response_data = response.json()
            print(response_data)
            response_data = eval(response_data['result'][1:-1])
            
        else:
            print('Error receiving data')
            return
        
        self.all_found = []
        for index, row in self.data.iterrows():
            for col in self.data.columns:
                if row[col] == 1:
                    print(col, row[col])
                    self.all_found.append(col)
        
        print(self.all_found)
        
        data = {
            'fileName':self.fileName, 
            'class_lr':response_data['class_lr'],
            'class_dt':response_data['class_dt'],
            'class_rf':response_data['class_rf']
        }
        
        asyncio.run(self.updatePermissionCount(data))
        
        print('data',data)
        
        return data
    
    async def updatePermissionCount(self, data):
        
        # print('found',len(self.all_found))
        # print(self.all_found)
        for permission in self.all_found:
            # print(permission)
            obj = await sync_to_async(PermissionCount.objects.get)(name=permission)
            
            if (data['class_rf']+data['class_dt']+data['class_lr'])/3 > 0.5:
                obj.malicious_count += 1
            else:
                obj.genuine_count += 1
            await sync_to_async(obj.save)()