from django.shortcuts import render
from django.views import generic
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from gmaps.models import PointOfInterest
import os
import json
import simplejson
from django.http import JsonResponse
from django.http import HttpResponse

from gmaps.models import PointOfInterest
from django.shortcuts import render_to_response, get_object_or_404, redirect

def gmaps(request):
    zone=PointOfInterest.objects.all()
    return render(request, 'gmaps/gmaps.html', {"zone": zone})

def ajax(request):
    script_dir = os.path.dirname(__file__)
    file_path = os.path.join(script_dir, 'static/gmaps/postes.json')    
    #data1 = []
    #with open(file_path) as f:
    #    for line in f:
    #        data1.append(json.load(line))
    json_data = open(file_path)
    data1 = json.load((json_data))
    #data2 = json.dumps(json_data)
        #f.close()
    #json_data.close()
    #return HttpResponse(simplejson.dumps(data1), content_type='application/json')
    return JsonResponse(data1,safe=False)
#def showgmapsDetail(request, zone_id):
 #   zone=PointOfInterest.objects.get(id=zone_id)
 #   return render_to_response('zonendetail.html', {"zone": zone})
