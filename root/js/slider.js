
// slider logic from JailbreakMe (Star)
// with foxlet&stek additions (added MNT_NOSUID)
(function(onSlid) {
    var thumbtack = document.getElementById('thumbtack');
    var hint = document.getElementById('hint');

    var hintHideRatio = 1/4;
    var slidRatio = 0.9;

    var left = 0;
    var startX = null;
    var maxLeft = thumbtack.parentNode.clientWidth - thumbtack.clientWidth - 5;
    var startLeft = null;

    // Set spacing by margin (hack)

    function set_left(left_) {
        left = left_;
        hint.style.opacity = 1 - (left_ / (maxLeft * hintHideRatio));
        thumbtack.style.marginLeft = left_ + 'px';
    }

    var onDown = function(x) {
        startX = x;
        startLeft = left;
        thumbtack.style.WebkitTransitionProperty = '';
        thumbtack.style.WebkitTransitionDuration = '0s';
        return false;
    }

    var onMove = function(x) {
        if (startX == null) return;

        var diff = x - startX;

        if (diff < 0) {
            diff = 0;
        } else if (diff >= maxLeft) {
            diff = maxLeft;
        }

        set_left(diff + startLeft);
    }

    var onEnd = function() {
        if (startX == null) return;
        startX = null;

        if (left/maxLeft >= slidRatio) {
            set_left(maxLeft);
            onSlid();
            return false;
        }

        var left_ = left;
        set_left(0);
        thumbtack.style.WebkitTransform = 'translateX(' + left_ + 'px)';

        setTimeout(function() {
            thumbtack.style.WebkitTransitionProperty = '-webkit-transform';
            thumbtack.style.WebkitTransitionDuration = '0.25s';
            thumbtack.style.WebkitTransform = 'translateX(0px)';
        }, 0);

        return false;
    }

    thumbtack.ontouchstart = e => onDown(e.targetTouches[0].clientX);
    window.ontouchmove = e => onMove(e.targetTouches[0].clientX);
    window.ontouchend = e => onEnd();

    thumbtack.onmousedown = e => onDown(e.clientX);
    window.onmousemove = e => onMove(e.clientX);
    window.onmouseup = e => onEnd();

    return this;
})(() => alert('Slider slid!'))

// Disable vertical scrolling in webapp
window.ontouchstart = function(e) { 
    e.preventDefault();
    return false;
}