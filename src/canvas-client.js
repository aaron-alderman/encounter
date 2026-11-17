'use strict';

(() => {
  const stage=document.querySelector('[data-canvas-stage]');
  if(!stage) return;
  const canvas=stage.querySelector('canvas');
  if(!canvas.getContext('2d')) return;
  const wasm=loadBrowserWasm(encounterCanvasWasm);
  const controls=selectBrowserPolicy(wasm);
  const textResult=value=>typeof value==='bigint'?browserWasmTextResult(wasm.memory,value):value;
  const start=Number(canvas.dataset.canvasStart);
  const duration=Number(canvas.dataset.canvasSeconds);
  const cueList=[...stage.querySelectorAll('[data-canvas-effect]')].map(({dataset})=>({
    effect:dataset.canvasEffect, from:Number(dataset.canvasFrom), to:Number(dataset.canvasTo)
  }));
  const scrub=stage.querySelector('[data-canvas-scrub]');
  const play=stage.querySelector('[data-canvas-play]');
  const audio=stage.querySelector('[data-canvas-audio]');
  const sound=stage.querySelector('[data-canvas-sound]');
  const time=stage.querySelector('[data-canvas-time]');
  const status=stage.querySelector('[data-canvas-status]');
  if(!controls){
    status.textContent='This release requires WebAssembly to play the canvas.';
    play.disabled=true;
    return;
  }
  const [admitted,timelineNotice]=controls.timelineAdmission(canvasNumbersAllowed(start,duration));
  if(!admitted){
    status.textContent=textResult(timelineNotice);
    play.disabled=true;
    return;
  }
  const paint=encounterCanvasPainter(canvas,timeline,textResult);
  const [assignment,separator]=controls.settingsText().map(textResult);
  const [formId,fieldSelector,resetSelector,draftSelector,outputAttribute]=controls.settingsSurface().map(textResult);
  const settingsForm=()=>document.getElementById(formId);
  const fields=()=>[...settingsForm().querySelectorAll(fieldSelector)];
  let settings={}, position=0, playing=false, audioPlaying=false, anchor=0, frame=0, playToken=0;
  let submission=null;

  function timeline(operation,...values){
    const implementation=canvasTimelinePolicy(controls,values);
    if(implementation===wasm&&(operation==='sceneFrame'||operation==='drawingVertex')){
      const [name,value]=values;
      return wasm[operation](...browserWasmText(wasm.memory,name),value);
    }
    return implementation[operation](...values);
  }

  function resetClock(){
    anchor=timeline('clockAnchor',performance.now(),position);
  }

  function readSettings(){
    const changes=[];
    for(const control of fields()){
      const {canvasSetting:key,canvasUnit:unit,canvasSaved:saved}=control.dataset;
      const value=Number(control.value);
      settings[key]=value;
      settingsForm().querySelector('['+outputAttribute+'="'+CSS.escape(key)+'"]').value=control.value+unit;
      const current=control.value;
      const changed=wasm
        ? browserWasmTextChanged(wasm.memory,controls.settingChanged,current,saved)
        : controls.settingChanged(current.length,saved?.length??-1,current,saved);
      if(changed)changes.push(control.labels[0].querySelector('span').textContent+assignment+current+unit);
    }
    settingsForm().querySelector(draftSelector).value=changes.join(separator);
    render();
  }

  function render(){
    const absolute=timeline('frameTime',start,position,duration);
    for(const {effect,from,to} of cueList){
      const validBounds=canvasNumbersAllowed(from,to);
      const [selected,offset]=timeline('cueSelection',absolute,validBounds,validBounds?from:0,validBounds?to:0);
      if(!selected)continue;
      paint(effect,timeline('cueTime',offset,settings.motion),settings);
      break;
    }
    scrub.value=String(position);
    const [minutes,seconds,separator,padding]=timeline('clockDisplay',position);
    time.value=minutes+textResult(separator)+textResult(padding)+seconds;
  }

  function stop(label){
    playToken++;
    playing=false;
    audioPlaying=false;
    cancelAnimationFrame(frame);
    audio.pause();
    play.textContent=label;
  }

  function tick(now){
    if(!playing)return;
    const audioTime=audioPlaying?audio.currentTime:0;
    const [next,ended,stopLabel]=timeline('playback',audioPlaying,audioTime,start,now,anchor,duration);
    position=next;
    render();
    if(ended)stop(textResult(stopLabel));
    else frame=requestAnimationFrame(tick);
  }

  async function startSound(token){
    let failed=false;
    try{
      audio.currentTime=timeline('audioPosition',start,position);
      await audio.play();
    }catch{
      failed=true;
    }
    const [useAudio,pause,reset,notice]=controls.narrationResult(token,playToken,playing,sound.checked,failed,audioPlaying);
    audioPlaying=Boolean(useAudio);
    if(pause)audio.pause();
    if(reset)resetClock();
    const message=textResult(notice);
    if(message)status.textContent=message;
  }

  play.addEventListener('click',()=>{
    const [stopPlayback,next,startNarration,playLabel]=timeline('playToggle',playing,position,duration,sound.checked);
    const label=textResult(playLabel);
    if(stopPlayback){stop(label);return;}
    position=next;
    status.textContent='';
    playing=true;
    resetClock();
    play.textContent=label;
    const token=++playToken;
    if(startNarration)void startSound(token);
    frame=requestAnimationFrame(tick);
  });
  sound.addEventListener('change',()=>{
    const token=++playToken;
    const [startNarration,useAnimationClock]=controls.soundChange(playing,sound.checked);
    if(startNarration)void startSound(token);
    if(useAnimationClock){
      audioPlaying=false;
      audio.pause();
      resetClock();
    }
  });
  scrub.addEventListener('input',()=>{
    const [next,seekAudio]=timeline('scrub',Number(scrub.value),duration,audioPlaying);
    position=next;
    resetClock();
    if(seekAudio)audio.currentTime=timeline('audioPosition',start,position);
    render();
  });
  audio.addEventListener('error',()=>{
    const [useAudio,reset,notice]=controls.narrationFault(playing,audioPlaying);
    audioPlaying=Boolean(useAudio);
    if(reset)resetClock();
    const message=textResult(notice);
    if(message)status.textContent=message;
  });
  function settingsEvent(event,matched){
    const kind=wasm?browserWasmText(wasm.memory,event.type):[event.type];
    const [read,reset,trackSubmission,clearSubmission,notify]=controls.settingsAction(...kind,matched);
    if(trackSubmission)submission=event;
    if(clearSubmission)submission=null;
    if(reset){
      for(const input of fields())input.value=input.dataset.canvasDefault;
    }
    if(read)readSettings();
    if(notify)settingsForm().dispatchEvent(new Event('input',{bubbles:true}));
  }
  document.addEventListener('input',event=>settingsEvent(event,event.target.matches(fieldSelector)),true);
  document.addEventListener('click',event=>settingsEvent(event,Boolean(event.target.closest(resetSelector))));
  document.addEventListener('submit',event=>settingsEvent(event,event.target===settingsForm()));
  window.addEventListener('beforeunload',event=>{
    const form=settingsForm();
    const dirty=Boolean(form?.querySelector(draftSelector)?.value);
    if(!controls.confirmLeave(submission?.target===form,Boolean(submission?.defaultPrevented),dirty))return;
    event.preventDefault();
    event.returnValue='';
  });
  document.addEventListener('encounter:live-refresh',event=>settingsEvent(event,false));
  readSettings();
})();
