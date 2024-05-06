from django.shortcuts import render,redirect
from aima.settings import BASE_DIR
from .models import Apk, AnalysisHistory
from .verifyapp import verifyApp
import os
from asgiref.sync import sync_to_async
from django.http import JsonResponse
from .models import PermissionCount

appAnalyzer = verifyApp()
appAnalyzer.initDataBase()

session={'msg':'', 'fileName':''}

def redirectURL(request):
    return redirect('/home/')

def populatePermissionCount(request):
    permissions = [
    'transact',
    'onServiceConnected',
    'bindService',
    'attachInterface',
    'ServiceConnection',
    'android.os.Binder',
    'SEND_SMS',
    'Ljava.lang.Class.getCanonicalName',
    'Ljava.lang.Class.getMethods',
    'Ljava.lang.Class.cast',
    'Ljava.net.URLDecoder',
    'android.content.pm.Signature',
    'android.telephony.SmsManager',
    'READ_PHONE_STATE',
    'getBinder',
    'ClassLoader',
    'Landroid.content.Context.registerReceiver',
    'Ljava.lang.Class.getField',
    'Landroid.content.Context.unregisterReceiver',
    'GET_ACCOUNTS',
    'RECEIVE_SMS',
    'Ljava.lang.Class.getDeclaredField',
    'READ_SMS',
    'getCallingUid',
    'Ljavax.crypto.spec.SecretKeySpec',
    'android.intent.action.BOOT_COMPLETED',
    'USE_CREDENTIALS',
    'MANAGE_ACCOUNTS',
    'android.content.pm.PackageInfo',
    'KeySpec',
    'TelephonyManager.getLine1Number',
    'DexClassLoader',
    'HttpGet.init',
    'SecretKey',
    'Ljava.lang.Class.getMethod',
    'System.loadLibrary',
    'android.intent.action.SEND',
    'Ljavax.crypto.Cipher',
    'WRITE_SMS',
    'READ_SYNC_SETTINGS',
    'android.telephony.gsm.SmsManager',
    'WRITE_HISTORY_BOOKMARKS',
    'TelephonyManager.getSubscriberId',
    'mount',
    'INSTALL_PACKAGES',
    'Runtime.getRuntime',
    'Ljava.lang.Object.getClass',
    'READ_HISTORY_BOOKMARKS',
    'Ljava.lang.Class.forName',
    'Binder',
]
    p_objects = [PermissionCount(name=permission) for permission in permissions]
    PermissionCount.objects.bulk_create(p_objects)
    return redirect('/home/')

def home(request):
    apks = AnalysisHistory.objects.all()
    if len(apks) > 0:
        AnalysisHistory.objects.all().delete()
    return render(request, r'appform\uploadApk.html', {'msg': session['msg']})

def store_apk(request):
    if request.method == 'POST':
        apk = request.FILES['apk']
        # print(apk)
        session['fileName']=apk
        Apk.objects.create(file=apk, file_name=apk)
        session['fileName'] = Apk.objects.last().file_name
        session['msg']='File Uploaded Successfully'
        return redirect('/wait-page/')
    else:
        session['msg']='File Upload Failed'
        return redirect('/home/')

def waitPage(request):
    return render(request, r'appform\waiting.html')

async def analyzeApk(request):
    global appAnalyzer
    # filePath=os.path.join(BASE_DIR, 'media\\apks', session['fileName'])
    appAnalyzer.verifyAppIfMallicious(os.path.join(BASE_DIR, f'media{os.path.sep}apks', session['fileName']))
    data = await sync_to_async(appAnalyzer.getFinalResult)()
    # print(data)
    print('Analysis Done')
    await sync_to_async(AnalysisHistory.objects.create)(file_name=session['fileName'], class_rf=data['class_rf'], 
                                    class_dt=data['class_dt'], class_lr=data['class_lr'])
    return JsonResponse({'status': 'completed'})

def showResult(request):
    apks = Apk.objects.all()
    if len(apks) > 0:
        Apk.objects.all().delete()
    
    for i in os.listdir(os.path.join(BASE_DIR, f'media{os.path.sep}apks')):
        os.remove(os.path.join(BASE_DIR, f'media{os.path.sep}apks', i))
        # print(i)
    
    data = AnalysisHistory.objects.get(file_name=session['fileName'])
    
    # get top 10 malicious permissions
    malicious_permissions = PermissionCount.objects.order_by('-malicious_count')[:10]
    
    # get top 5 genuine permissions
    genuine_permissions = PermissionCount.objects.order_by('-genuine_count')[:5]
    
    return render(request, r'appform\result.html', {'data': data, 'm_p': malicious_permissions, 'g_p': genuine_permissions})