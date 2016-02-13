from django.db import connections
from django.db.models import Count
from django.http import JsonResponse
from django.shortcuts import render
import json




def lm(request):
    return render(request, 'lm/lm.html')

#def miserables(request):
 #   json_data = open('lm/static/miserables.json') 
 #   data1 = json.load(json_data) 
 #   data2 = json.dumps(json_data)
 #   return JsonResponse(list(data1), safe=False)