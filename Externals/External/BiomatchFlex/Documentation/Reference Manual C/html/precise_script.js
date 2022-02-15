 document.getElementsByClassName = function(cl) {
    var retnode = [];
    var myclass = new RegExp('\\b'+cl+'\\b');
    var elem = this.getElementsByTagName('*');
    for (var i = 0; i < elem.length; i++) {
     var classes = elem[i].className;
     if (myclass.test(classes)) retnode.push(elem[i]);
    }
    return retnode;
 };

 var i = 0;
 var m = document.getElementsByClassName("tabs");

 while(m[i]) {
  i++;
 }

 var newcontent         = document.createElement('img');
 newcontent.id          = 'precise_logo';
 newcontent.src         = 'PRECISE_logo_webb_ca65.jpg';
 newcontent.alt         = 'Precise Biometrics logotype';
 newcontent.className   = 'precise_logo';
 
 var sibling = m[i-1].nextSibling;
 sibling.parentNode.insertBefore(newcontent,sibling); 
