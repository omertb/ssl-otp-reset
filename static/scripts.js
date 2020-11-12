$(document).ready(function(){
    $("#onBehalf").change(function(){
        $(this).find("option:selected").each(function(){
            var optionValue = $(this).attr("value");
            if(optionValue=='Myself'){
                $("#thirdPartyUserArea").hide();
                document.getElementById('thirdPartyUser').value = '';
            } else{
                $("#thirdPartyUserArea").fadeIn("slow");
            }
        });
    }).change();
});

$(document).ready(function() {
  $('.btn').on('click', function() {
    var $this = $(this);
    var loadingText = '<i class="fa fa-circle-o-notch fa-spin"></i> loading...';
    if ($(this).html() !== loadingText) {
      $this.data('original-text', $(this).html());
      $this.html(loadingText);
    }
    setTimeout(function() {
      $this.html($this.data('original-text'));
    }, 4000);
  });
});