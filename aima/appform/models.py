from typing import Any
from django.db import models

class Apk(models.Model):
    file = models.FileField(upload_to='apks/')
    file_name = models.CharField(max_length=100, null=True, blank=True)
    
    def __str__(self) -> str:
        return self.file_name

class AnalysisHistory(models.Model):
    file_name = models.CharField(max_length=100, null=False, blank=False)
    class_rf = models.IntegerField(null=False, blank=False)
    class_dt = models.IntegerField(null=False, blank=False)
    class_lr = models.IntegerField(null=False, blank=False)
    
    def __str__(self) -> str:
        return self.file_name

class PermissionCount(models.Model):
    name = models.CharField(max_length=200)
    malicious_count = models.IntegerField(default=0)
    genuine_count = models.IntegerField(default=0)
    
    def __str__(self) -> str:
        return str(self.name)+' '+str(self.malicious_count)+' '+str(self.genuine_count) 