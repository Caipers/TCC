
                setLines(null); 
                setWindow(null); 
                var originPoint = this.getPosition();
                var oLat = parseFloat(this.getPosition().lat());
                var oLng = parseFloat(this.getPosition().lng());
                for (var k = 0, length = userPos[i][3].length; k < length ; k++) {
                for (j = 0; j<32 ; j++){
                
                    if(userPos[i][3][k].nwkAdr==userPos[j][0])
                  {
                    //cont1+=1;

                    //window.alert(userPos[i][3][k].nwkAdr);
                    //window.alert(userPos[j][0]);
                     var coord = [
                    
                    {lat: userPos[i][1], lng: userPos[i][2]},
                    {lat: userPos[j][1], lng: userPos[j][2]}
                    ];
                    var color;

                    var out1 = (userPos[i][3][k].tot_out_cost/userPos[i][3][k].tot_pkt).toFixed(2);
                    var in1 = (userPos[i][3][k].tot_in_cost/userPos[i][3][k].tot_pkt).toFixed(2);            

                    if (in1 < out1)
                      men = out1;
                    else if (in1 >= out1)
                      men = in1;

                    if(men > 5)
                      color =  '#FF0000';
                    else if((men > 3) && (men <= 5))
                      color = '#FFFF00';
                    else if (men <= 3)
                      color = '#00FF00'


                    var lineSymbol = {
                      path: google.maps.SymbolPath.FORWARD_OPEN_ARROW,
                            scale: 2.5
                          };
                           var link = new google.maps.Polyline({
                        path: coord,
                        geodesic: true,
                        strokeColor: color,
                        strokeOpacity: 1.0,
                        strokeWeight: 2
                        /*icons: [{
                        icon: lineSymbol,
                        offset: '45%',


                        }]*/

                      });

                link.setMap(map);



                    arrayLine.push(link);



                    google.maps.event.addListener(link, 'click', (function(link, i, k, j) {
                    return function() {
                      setWindow(null); 

                        //infowindow.setContent(userPos["pontos"][i].nome+'<br>'+userPos["pontos"][i].desc);
                        infowindow1.setContent('Custo de saída: '+ (userPos[i][3][k].tot_out_cost/userPos[i][3][k].tot_pkt).toFixed(2) + '<br>Custo de entrada: ' + (userPos[i][3][k].tot_in_cost/userPos[i][3][k].tot_pkt).toFixed(2) );
                        //infowindow.setContent('<p><b>Intensidade: </b> '+userPos["links"][i].intensidade );
                        //window.alert('pos1:'+userPos[i][1]+'pos2'+userPos[j][1]+'div'+(userPos[i][1] + userPos[j][1])/2);
                          mLat = (userPos[i][1]+userPos[j][1])/2;
                          mLon = (userPos[i][2]+userPos[j][2])/2;
                          var position1 = new google.maps.LatLng(mLat,mLon);
                        infowindow1.setPosition(position1);
                        infowindow1.open(map);
                        infowindows.push(infowindow1);
                          }
                      })(link, i, k, j));
                        }
                        }
              }
                infowindow.setContent('Network Adress: ' + userPos[i][0] + '<br>' +'Mac Adress: ' + userPos[i][4] + '<br>' + ' Número de vizinhos: ' + userPos[i][3].length +'<br>' + "<a href='javascript:drawChart("+marker+");'>Lista de Vizinhos</a>");
                infowindow.open(map, marker);
                //infowindows.push(infowindow);
                  };