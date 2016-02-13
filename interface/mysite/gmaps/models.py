from django.db import models
#from geoposition import Geoposition
#from geoposition.fields import GeopositionField

class PointOfInterest(models.Model):
    name = models.CharField(max_length=100)
    #position = GeopositionField()
    lng = models.DecimalField(max_digits=10, decimal_places=7)
    lat = models.DecimalField(max_digits=10, decimal_places=7)
    def as_json(self):
        return dict(lat=str(self.lat),lng=str(self.long))
    def __unicode__(self):
        return "long: %s \nlat: %s\n" %  (str(self.lat), str(self.long))
