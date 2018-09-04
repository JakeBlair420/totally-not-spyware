if(
    !/\b10_\S+ like Mac OS X/.test(navigator.userAgent)
    //&& !/\b11_\S+ like Mac OS X/.test(navigator.userAgent)
)
{
    // #i_can_haz_buttloop
    (window.crypto.subtle || window.crypto.webkitSubtle).digest(
        {'name':'SHA-1'},
        str2ab(window.location.hash)
    ).then(function(x) {
        if(hexlify(new Uint8Array(x)) != '9e04130fa02fc3c416f28ba556f0165da4d93054')
            throw null;
    }).catch(function(){
        document.title = 'Incompatible Spyware';
        var body = document.body;
        while(body.firstChild)
        {
            body.removeChild(body.firstChild);
        }
        var center = document.createElement('div');
        center.className = 'center';
        center.appendChild(document.createElement('h1')).textContent = 'Hello from the NSA!';
        center.appendChild(document.createElement('h2')).textContent = "Unfortunately this spyware is only compatible with iOS 10. You're not on that version, so don't try it. At all. It will break something. Seriously. Forget we said anything.";
        body.appendChild(center);
        body.className = 'incompatible';

        window.ontouchmove  = undefined;
        window.ontouchend   = undefined;
        window.onmousemove  = undefined;
        window.onmouseup    = undefined;
        window.ontouchstart = function(e)
        {
            e.preventDefault();
            return false;
        };
    });
}
