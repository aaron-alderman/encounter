'use strict';

// Canvas 2D drawing effects. A surface declares the cue order and treatment.
function encounterCanvasPainter(canvas,timeline,textResult) {
  const [W,H,alpha]=timeline('surfaceProfile');
  canvas.width=W; canvas.height=H;
  const ctx=canvas.getContext('2d',{alpha:Boolean(alpha)});
  const [bands,waves,middleStop,glowX,glowY,glowRadius,glowAlpha]=timeline('seaLayout');
  let treatment;
  const drawings=new Map();
  const styles=new Map();
  function style(value){
    if(!styles.has(value))styles.set(value,textResult(value));
    return styles.get(value);
  }
  const [teal,foam,paper,coral,amber,slate]=timeline('palette').map(style);
  const P={teal,foam,paper,coral,amber,slate};
  const dot=(x,y,r,c)=>{ctx.fillStyle=c;ctx.beginPath();ctx.arc(x,y,r,0,2*Math.PI);ctx.fill()};
  const path=(pts,c,w=2)=>{ctx.strokeStyle=c;ctx.lineWidth=w;ctx.lineCap='round';ctx.lineJoin='round';ctx.beginPath();pts.forEach(([x,y],i)=>i?ctx.lineTo(x,y):ctx.moveTo(x,y));ctx.stroke()};
  const shape=(pts,c)=>{ctx.fillStyle=c;ctx.beginPath();pts.forEach(([x,y],i)=>i?ctx.lineTo(x,y):ctx.moveTo(x,y));ctx.closePath();ctx.fill()};
  function light(x,y,r,color,alpha=1){
    ctx.save();ctx.globalAlpha=timeline('lightAlpha',alpha,treatment.light);
    const glow=ctx.createRadialGradient(x,y,1,x,y,r);glow.addColorStop(0,color);glow.addColorStop(1,'transparent');
    ctx.fillStyle=glow;ctx.fillRect(x-r,y-r,r*2,r*2);ctx.restore();
  }
  function sea(t,warm){
    ctx.setTransform(1,0,0,1,0,0);
    const [surface,middle,depth,glow]=timeline('waterStyle',warm).map(style);
    const gr=ctx.createLinearGradient(0,0,0,H);gr.addColorStop(0,surface);gr.addColorStop(middleStop,middle);gr.addColorStop(1,depth);ctx.fillStyle=gr;ctx.fillRect(0,0,W,H);
    light(glowX,glowY,glowRadius,glow,glowAlpha);
    for(let j=0;j<bands;j++){
      for(let i=0;i<waves;i++){
        const [x,y,crestX,crestY,endX,ink,width]=timeline('seaWave',t,j,i);
        path([[x,y],[crestX,crestY],[endX,y]],style(ink),width);
      }
    }
  }
  function camera(z,dx,dy){
    const {pan,zoom}=treatment;
    const [x,y,scale,originX,originY]=timeline('camera',W,H,dx,dy,z,zoom,pan);
    ctx.translate(x,y);ctx.scale(scale,scale);ctx.translate(originX,originY);
  }
  function plate(x,y,rx,ry,depth,top=P.teal){
    const [left,right,crest,bottom,edge,face]=timeline('plateGeometry',x,y,rx,ry,depth);
    shape([[left,y],[x,bottom],[x,face],[left,edge]],'#24434a');
    shape([[x,bottom],[right,y],[right,edge],[x,face]],'#315e60');
    shape([[left,y],[x,crest],[right,y],[x,bottom]],top);
    path([[left,y],[x,crest],[right,y]],'#d6f5d285',2);
  }
  function beacon(x,y,k=1,on=true,t=0){
    const [plateY,plateWidth,plateHeight,plateDepth]=timeline('beaconLayout',y,k);
    plate(x,plateY,plateWidth,plateHeight,plateDepth,P.slate);
    const atBeacon=name=>vertices(name).map(([dx,dy])=>timeline('placeVertex',x,y,k,dx,dy));
    shape(atBeacon('beacon-tower'),P.paper);
    shape(atBeacon('beacon-shadow'),'#acad91');
    const [stripeLeft,stripeRight,stripeTop,stripeBottom,stripeWidth]=timeline('beaconStripes',x,y,k);
    for(const stripeY of [stripeTop,stripeBottom]){
      path([[stripeLeft,stripeY],[stripeRight,stripeY]],P.coral,stripeWidth);
    }
    shape(atBeacon('beacon-window'),on?P.amber:P.slate);
    shape(atBeacon('beacon-roof'),P.coral);
    if(on){
      const [glowY,glowRadius,alpha,lampY,lampRadius]=timeline('beaconGlow',t,y,k);
      light(x,glowY,glowRadius,P.amber,alpha);
      dot(x,lampY,lampRadius,P.foam);
      for(let j=0;j<11;j++){
        const [py,left,right,strokeWidth,ink]=timeline('beaconReflection',t,j,k,y,x);
        path([[left,py],[right,py]],style(ink),strokeWidth);
      }
    }
  }
  function book(x,y,k,o=1){
    const [left,right,foot,outerBottom,outerTop,spineTop,spineLineTop,spineLineBottom]=timeline('bookGeometry',x,y,k,o);
    const a=[[x,foot],[left,outerBottom],[left,outerTop],[x,spineTop]];
    const b=[[x,foot],[right,outerBottom],[right,outerTop],[x,spineTop]];
    ctx.save();ctx.shadowColor='#05161d';ctx.shadowBlur=21;ctx.shadowOffsetY=12;
    shape(a,'#d0cca2');shape(b,P.paper);ctx.restore();
    path([[x,spineLineTop],[x,spineLineBottom]],'#426669',3*k);
    const [details,detailLeft,lineWidth,markWidth,markRadius]=timeline('bookDetails',x,k,o);
    if(details){
      const points=[];
      const colors=[];
      for(let i=0;i<4;i++){
        const [lineX,fromY,toY,markX,markY,accent]=timeline('bookDetailGeometry',x,y,k,o,i);
        path([[lineX,fromY],[detailLeft,toY]],'#789583',lineWidth);
        points.push([markX,markY]);
        colors.push(accent?P.coral:'#40847a');
      }
      path(points,'#4f8e81',markWidth);
      points.forEach(([px,py],i)=>dot(px,py,markRadius,colors[i]));
    }
  }
  function slip(x,y,k=1,angle=0,ink=P.teal){
    ctx.save();ctx.translate(x,y);ctx.rotate(angle);ctx.scale(k,k);
    ctx.shadowColor='#081722';ctx.shadowBlur=12;ctx.shadowOffsetY=5;
    shape(vertices('slip-paper'),P.paper);
    ctx.shadowBlur=0;ctx.shadowOffsetY=0;shape(vertices('slip-fold'),ink);
    for(const line of ['slip-line-top','slip-line-middle','slip-line-bottom'])path(vertices(line),ink,2);
    ctx.restore();
  }
  function vertices(name){
    if(drawings.has(name))return drawings.get(name);
    const points=[];
    for(let index=0;;index++){
      const [exists,x,y]=timeline('drawingVertex',name,index);
      if(!exists)break;
      points.push([x,y]);
    }
    drawings.set(name,points);
    return points;
  }
  function route(pts,q,c=P.foam,width=4){
    path(pts,'#90d0bf42',2);
    let total=0;
    const sizes=pts.slice(1).map(([x,y],i)=>{
      const [fromX,fromY]=pts[i];
      const [length,next]=timeline('routeSegment',fromX,fromY,x,y,total);
      total=next;
      return length;
    });
    let left=timeline('routeDistance',total,q),last=pts[0];
    const active=[last];
    for(let i=0;i<sizes.length;i++){
      const [fromX,fromY]=pts[i], [toX,toY]=pts[i+1];
      const [draw,x,y,remaining]=timeline('routePoint',fromX,fromY,toX,toY,left,sizes[i]);
      if(!draw)break;
      last=[x,y];
      active.push(last);left=remaining;
    }
    if(active.length>1){ctx.save();ctx.shadowColor=c;ctx.shadowBlur=13;path(active,c,width);ctx.restore()}
    dot(last[0],last[1],4,c);return last;
  }
  function boat(x,y,k,t,color=P.amber){
    ctx.save();ctx.translate(x,timeline('boatBob',t,y));ctx.scale(k,k);
    for(let i=0;i<3;i++){
      const [alpha,rx,ry]=timeline('boatWake',t,i);
      ctx.strokeStyle='rgba(180,243,222,'+alpha+')';
      ctx.beginPath();ctx.ellipse(0,21,rx,ry,0,0,Math.PI*2);ctx.stroke();
    }
    shape(vertices('boat-hull'),P.teal);
    path(vertices('boat-mast'),P.paper,3);
    shape(vertices('boat-main-sail'),color);
    shape(vertices('boat-small-sail'),P.paper);ctx.restore();
  }
  function pulse(x,y,t,color){
    light(x,y,43,color,.26);
    for(let j=0;j<3;j++){
      const [alpha,rx,ry]=timeline('pulseRing',t,j);
      ctx.save();ctx.globalAlpha=alpha;ctx.strokeStyle=color;
      ctx.beginPath();ctx.ellipse(x,y,rx,ry,0,0,2*Math.PI);ctx.stroke();ctx.restore();
    }
  }
  function flight(t){
    for(let j=0;j<47;j++){
      const [x,y,radius]=timeline('flightStar',t,j);
      dot(x,y,radius,'#a9e8d37e');
    }
    const [x,y]=timeline('flightPosition',t);
    for(let j=0;j<6;j++){
      const [trailX,trailY,radius]=timeline('flightTrail',t,j,x,y);
      dot(trailX,trailY,radius,P.coral);
    }
    shape(vertices('flight-craft').map(([dx,dy])=>timeline('placeVertex',x,y,1,dx,dy)),P.paper);
    for(let j=0;j<6;j++){
      const [plateX,plateY,slate,width,height,depth]=timeline('flightPlate',t,j);
      plate(plateX,plateY,width,height,depth,slate?P.slate:P.teal);
    }
    const [visible,alpha,beaconX,beaconY,glowRadius,lampRadius]=timeline('flightBeacon',t);
    if(visible){light(beaconX,beaconY,glowRadius,P.amber,alpha);dot(beaconX,beaconY,lampRadius,P.amber)}
  }
  function launch(t){
    plate(830,434,258,81,23,P.slate);
    const [opening,progress]=timeline('launchPhase',t);
    book(826,321,1.12,opening);
    for(let j=0;j<4;j++){
      const [x,y,rotation,coral]=timeline('launchSlip',t,j);
      slip(x,y,.70,rotation,coral?P.coral:P.teal);
    }
    route(vertices('launch'),progress,P.foam,4);
  }
  function arrival(t,still=false){
    beacon(928,343,1.23,true,t);
    plate(327,512,180,58,21,P.teal);
    const [progress,boatTime]=timeline('arrivalPhase',t,still);
    const [x,y]=route(vertices('arrival'),progress,P.foam);
    boat(x,y,1.13,boatTime);
  }
  function collision(t){
    book(640,372,1.31,.92);
    for(let i=0;i<20;i++){
      const [visible,x,y,scale,rotation,teal]=timeline('collisionSlip',t,i);
      if(visible)slip(x,y,scale,rotation,teal?P.teal:P.coral);
    }
    const [visible,q]=timeline('collisionRoute',t);
    if(visible){
      route(vertices('collision-west'),q,P.coral,5);
      route(vertices('collision-east'),q,P.foam,5);
      pulse(626,443,t,P.coral);
    }
  }
  function intent(t){
    plate(640,489,298,99,24,P.slate);
    book(640,361,1.46,timeline('intentBook',t));
    for(const [i,color] of [P.teal,P.amber,P.foam,P.coral].entries()){
      const [visible,x,y,elbow,progress,scale,rotation]=timeline('intentSlip',t,i);
      if(!visible)continue;
      route([[640,376],[elbow,y],[x,y]],progress,color,3);
      slip(x,y,scale,rotation,color);
    }
  }
  function branches(t){
    const a=vertices('branch-first');
    const b=vertices('branch-second');
    plate(982,256,100,38,20,P.slate);beacon(1067,391,.82,true,t);
    const [first,second,firstBranch,boatRoute]=timeline('branchPhase',t);
    route(a,first,P.coral,4);
    route(b,second,P.foam,4);
    const [x,y]=route(firstBranch?a:b,boatRoute,firstBranch?P.coral:P.foam,4);
    boat(x,y,1,t,firstBranch?P.coral:P.amber);
  }
  function strata(t){
    for(let j=0;j<4;j++){
      const [x,y,rx,ry,depth,ink]=timeline('strataPlate',t,j);
      plate(x,y,rx,ry,depth,style(ink));
      const [edge,routeX,endY,showRoute,progress,width]=timeline('strataRoute',t,j,x,y);
      if(showRoute)route([[edge,y],[routeX,y],[routeX,endY]],progress,P.amber,width);
    }
    for(let i=0;i<12;i++){
      const [x,y]=timeline('strataStar',t,i);
      dot(x,y,2.5,'#a4e8cc83');
    }
  }
  function gate(t){
    const [open,lampReady,beacons,q]=timeline('gatePhase',t);
    const lamp=lampReady?P.foam:P.coral;
    beacon(446,355,.84,beacons,t);beacon(842,355,.84,beacons,t);
    const [x,y]=route(vertices('gate'),q,lamp,5);
    const [left,right,armY,leftBase,rightBase,baseY,width]=timeline('gateArms',open);
    path([[leftBase,baseY],[left,armY]],lamp,width);
    path([[rightBase,baseY],[right,armY]],lamp,width);
    pulse(643,400,t,lamp);
    boat(x,y,1.18,t,lamp);
  }
  function rebuild(t,refactor=false){
    const pts=vertices('rebuild');
    const [progress,routeProgress]=timeline('rebuildPhase',t,refactor);
    route(pts,routeProgress,P.amber,4);
    for(let i=0;i<3;i++){
      const [baseX,baseY]=pts[i+1];
      const [x,y]=timeline('rebuildPlate',t,progress,i,baseX,baseY,refactor);
      plate(x,y,93,38,22,[P.teal,P.slate,P.coral][i]);
    }
    if(refactor){
      book(640,303,1.20,1);pulse(185,496,t,P.foam);pulse(1100,496,t,P.foam);
    }else{
      slip(185,496,.9,-.17,P.teal);slip(1100,496,.9,.14,P.teal);
    }
  }
  function network(t){
    const nodes=Array.from({length:49},(_,i)=>timeline('networkNode',i));
    nodes.forEach(([x,y,peer])=>{
      path([[x,y],nodes[peer]],'#87cab038',1);
      dot(x,y,3,'#71aa9c70');
    });
    const marks=vertices('network');
    const q=timeline('networkProgress',t);
    route(marks,q,P.foam,4);
    marks.forEach(([x,y],j)=>{
      const [visible,pulseTime,card,angle]=timeline('networkMark',t,q,j);
      if(visible){
        pulse(x,y,pulseTime,P.amber);
        if(card)slip(x,y,.91,angle,P.amber);
      }
    });
  }
  function signals(t){
    const paths=['signal-west','signal-east','signal-south'].map(vertices);
    const phases=paths.map((_,i)=>timeline('signalPhase',t,i));
    paths.forEach((p,i)=>route(p,phases[i][0],[P.teal,P.amber,P.foam][i],4));
    for(const [,pulseTime,amber,x,y] of phases){
      const color=amber?P.amber:P.teal;
      pulse(x,y,pulseTime,color);plate(x,y,75,38,24,color);
    }
    book(640,365,.98,timeline('signalsBook',t));
  }
  function harbours(t){
    const q=timeline('harboursProgress',t);
    for(let i=0;i<2;i++){
      const [x,scale,plateY,beaconY,routeX,start,elbow,end]=timeline('harbourLayout',i);
      plate(x,plateY,184,69,23,P.slate);beacon(x,beaconY,scale,true,t);
      route([[routeX,start],[routeX,elbow],[x,end]],q,P.amber,4);
    }
    book(640,265,1.07,.92);
  }
  function home(t,ending=false){
    const [a,progress]=timeline('homePhase',t);
    const x=960,y=305;
    const grad=ctx.createLinearGradient(x,y-55,75,214+a);
    grad.addColorStop(0,'#ffd78b72');grad.addColorStop(1,'#ffd78b00');
    shape([[x,y-56],[53,116+a],[53,259+a]],grad);
    beacon(x,y,1.36,true,t);
    plate(618,494,130,42,20,P.slate);
    const [bx,by]=route(vertices('home'),progress,P.foam,4);
    boat(bx,by,1.24,t);
    if(ending){
      const [q,background,caption,ink,font]=timeline('closingFade',t);
      ctx.setTransform(1,0,0,1,0,0);ctx.fillStyle='rgba(7,22,30,'+background+')';ctx.fillRect(0,0,W,H);
      ctx.globalAlpha=q;ctx.fillStyle=style(ink);ctx.font=style(font);ctx.textAlign='center';ctx.textBaseline='middle';
      ctx.fillText(style(caption),640,331);path([[595,396],[685,396]],P.amber,2);ctx.globalAlpha=1;
    }
  }
  const scenes=[null,flight,launch,arrival,collision,intent,strata,branches,gate,rebuild,network,signals,harbours,home];
  return function paint(name,time,settings) {
    const [code,shotTime,offset,alternate]=timeline('sceneFrame',name,time);
    if (!code) return;
    treatment=settings;
    const [warm,zoom,x,y]=timeline('sceneCamera',code,shotTime,offset,alternate);
    sea(shotTime,warm);
    camera(zoom,x,y);
    scenes[code](shotTime,alternate);
    ctx.setTransform(1,0,0,1,0,0);
    const [alpha,color]=timeline('warmth',settings.warmth);
    const tint=style(color);
    if(tint){
      ctx.globalAlpha=alpha;
      ctx.globalCompositeOperation='soft-light';
      ctx.fillStyle=tint;
      ctx.fillRect(0,0,W,H);
      ctx.globalAlpha=1;
      ctx.globalCompositeOperation='source-over';
    }
  };
}
