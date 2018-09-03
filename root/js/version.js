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
        window.location.replace('incompatible.html');
    })
}
