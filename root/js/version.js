if(
    !/iPhone OS 10_/.test(navigator.userAgent)
    //&& !/iPhone OS 11_/.test(navigator.userAgent)
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
