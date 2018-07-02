// slider.js - slider logic from JailbreakMe (Star)

// Get slider's thumbtack object
var thumbtack = document.getElementById('thumbtack');

// Set spacing by margin (hack)
var left = 0;
function set_left(left_) {
    left = left_;
    thumbtack.style.marginLeft = left_ + 'px';
}

thumbtack.ontouchstart = function(e) {
    startX = e.targetTouches[0].clientX;
    startLeft = left;
    thumbtack.style.WebkitTransitionProperty = '';
    thumbtack.style.WebkitTransitionDuration = '0s';
    maxLeft = thumbtack.parentNode.clientWidth - thumbtack.clientWidth - 5;
    return false;
}

thumbtack.ontouchmove = function(e) {
    var diff = e.targetTouches[0].clientX - startX;
    if(diff < 0) diff = 0;
    else if(diff >= maxLeft) diff = maxLeft;
    set_left(diff + startLeft);
}

window.ontouchend = function() {
    if(startX == null) return;
    startX = null;
    if(maxLeft - left < 15) {
        return false;
    }
    var left_ = left;
    set_left(0);
    thumbtack.style.WebkitTransform = 'translateX('+left_+'px)';
    setTimeout(function() {
        thumbtack.style.WebkitTransitionProperty = '-webkit-transform';
        thumbtack.style.WebkitTransitionDuration = '0.25s';
        thumbtack.style.WebkitTransform = 'translateX(0px)';
    }, 0);
    return false;
}