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
import pyshark
import capture
import lib.geoPositioning

#########################################
script_dir = os.path.dirname(__file__)
PCAP_FILE = os.path.join(script_dir,'pcap_files/entire_park_05_03.PCAP')


cap = capture.capture()
nodes = cap.fileCapture(PCAP_FILE)

# f = file('nodes.log', 'w')
#script_dir = os.path.dirname(__file__)
file_path = os.path.join(script_dir, 'docs/geo_positions.csv') 
f = file_path
tot_in = 0
tot_out = 0
tot_pkt = 0
geo = lib.geoPositioning.geoPositioning(f)
i = 0
tmp=''
out1=''

file_path1 = os.path.join(script_dir, 'static/gmaps/postes1.json') 
with open(file_path1, 'w') as outfile:
    #json.dump(dash1,outfile)
    outfile.write('[')
    lim = 0 
    #print "Following nodes has been processed:"
    for node in nodes:
        values = geo.getValues(node.getMacAdr())
        # print "Values:",values
        if (values is None):
            # print "The Location of node",node.getMacAdr(),"has not been found"
            pass
        else:
            lim+=1

    print lim


    for node in nodes:
        #"""Node is a node object"""
        #print "Processing nodes"
        

        # print "Setting node positions"
        values = geo.getValues(node.getMacAdr())
        # print "Values:",values
        if (values is None):
            # print "The Location of node",node.getMacAdr(),"has not been found"
            pass
        else:
            node.setLocation(values["lat"], values["lon"])
            node.setSN(values["sn"])
            # print "Node",node.getMacAdr(),"has",node.getLocation(),"and following SN",node.getSN()

        
            # t_in, t_out = node.processPreNeighbors()
            tot_pkt += node.getPacketTotal()
            # tot_in += t_in
            # tot_out += t_out

            # print "\t",node.getPacketTotal(),'packets of node =>',node.getNwkAdr(),node.getMacAdr()
            # node.saveHistoricalNeighbors()

            # print "Basics of", node.getNwkAdr(),str(node.getJSONBasics())
            # print "Current neighbors",node.getJSONCurNeighbors()
            
            # if node.isResetedNode() == True:
            #     print "Node",node.getNwkAdr(),"is a reseted node"

            # **************************************************
            # tmp contais a 3D matrix (tmp[node][neighbors])
            # EXAMPLES
            # tmp[0] is the network address of this node
            # tmp[1] is the node's historical neighbors
            # tmp[1][0] is the first neighbor of the list of neighbors (a dictionary).
            # tmp[1][0]['nkwAdr'] to access the network address of the first neighbor.
            tmp = json.loads(node.getJSONHistoricalNeighbors())
            #out1 = tmp
            # ***************************************************

        
            

            
            json.dump(tmp, outfile) 
            i += 1    
            if (i != 0 and i != (lim)):
                
                outfile.write(',')
            #json.dump(',',outfile)
            #print json.loads(node.getJSONBasics())
            print i
        #json.dump(dash2,outfile)

    # print "Total of cost of incoming cost of all nodes =", tot_in
    # print "Total of cost of outcoming cost of all nodes =", tot_out
    outfile.write(']')
    #print out1

#########################################

from gmaps.models import PointOfInterest
from django.shortcuts import render_to_response, get_object_or_404, redirect

def gmaps(request):
    zone=PointOfInterest.objects.all()
    return render(request, 'gmaps/gmaps.html', {"zone": zone})

def ajax(request):
    script_dir = os.path.dirname(__file__)
    file_path = os.path.join(script_dir, 'static/gmaps/postes1.json')    
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
