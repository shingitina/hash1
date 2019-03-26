function MD5_test(){
    var target_str, result_str;
    target_str = document.myFrm.myTextBoxBefore.value;
    result_str = MD5Main(target_str);
    document.myFrm.myTextBoxAnswer.value = "" + result_str;
}
// �ȉ��̊֐������C���֐�
// �ȉ��̒l���R�s�[&�y�[�X�g���Ďg���΂����B
// �O���[�o���ȃX�R�[�v�����ϐ�
// ���ۂ́A�萔����
var MD5Round1S;
var MD5Round2S;
var MD5Round3S;
var MD5Round4S;
var MD5PADDING;
    // RFC1321 P10 �� S11�`S44 �� define
MD5Round1S = new Array(7,12,17,22);
MD5Round2S = new Array(5,9,14,20);
MD5Round3S = new Array(4,11,16,23);
MD5Round4S = new Array(6,10,15,21);
    // RFC1321 P10 �� PADDING[64]
MD5PADDING = new Array(128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
    // �O���[�o���ȃX�R�[�v�����ϐ�
    // MD5Main() �ŏ���������
        // ���͕����̃R�[�h���i�[����z��
var MD5IntInputData;
    // MD5 �̌���(�R�[�h)���i�[����z��
var MD5digest;
    // RFC1321 context �\���̂� count �z��
    // ����̒P�ʂ� bit
var MD5contextCount;
    // RFC1321 context �\���̂� state �z��
    // RFC1321 P4 �� word A,B,C,D
var MD5contextState;
    // RFC1321 context �\���̂� buffer �z��
var MD5contextBuffer;
    ///////////////////////////////////////
    // RFC1321 P10 �� define ����Ă��� F()
function MD5F(x,y,z){
    var ans;
    var temp;
    temp = BitNot(x);
    temp = temp & 0xffffffff;
    ans = BitOr(BitAnd(x,y),BitAnd(temp,z));
    return ans;
}
///////////////////////////////////////
// RFC1321 P10 �� define ����Ă��� G()
function MD5G(x,y,z){
     var ans;
     var temp;
     temp = BitNot(z);
     temp = temp & 0xffffffff;
     ans = BitOr(BitAnd(x,z),BitAnd(y,temp));
     return ans;
}
///////////////////////////////////////
// RFC1321 P10 �� define ����Ă��� H()
    function MD5H(x,y,z){
     var ans;
     
     ans = BitXor(BitXor(x,y),z);
     return ans;
    }
///////////////////////////////////////
// RFC1321 P10 �� define ����Ă��� I()
    function MD5I(x,y,z){
     var ans;
     var temp;
     temp = BitNot(z);
     temp = temp & 0xffffffff;
     ans = BitXor(y,BitOr(x,temp));
     return ans;
    }
///////////////////////////////////////
// RFC1321 P10 �� define ����Ă��� ROTATE_LEFT()
    function MD5ROTATE_LEFT(x,n){
     var ans;
     var ans1;
     var ans2;
     // ans1 = (x << n) & 0xffffffff;
     // ans2 = (x >>> (32-n)) & 0xffffffff;
     // ans = ans1 | ans2;
     ans1 = (x * Math.pow(2,n)) % 4294967296;
     ans2 = Math.floor(x / Math.pow(2,32-n));
     ans = ans1 + ans2;
     return ans;
    }
///////////////////////////////////////
// RFC1321 P10 �� define ����Ă��� FF()
    function MD5FF(a,b,c,d,x,s,ac){
     var ans;
     ans = (a + MD5F(b,c,d) + x + ac) % 4294967296;
     ans = MD5ROTATE_LEFT(ans,s);
     ans = (ans + b) % 4294967296;
     return ans;
    }
///////////////////////////////////////
// RFC1321 P11 �� define ����Ă��� GG()
    function MD5GG(a,b,c,d,x,s,ac){
     var ans;
     ans = (a + MD5G(b,c,d) + x + ac) % 4294967296;
     ans = MD5ROTATE_LEFT(ans,s);
     ans = (ans + b) % 4294967296;
     return ans;
    }
///////////////////////////////////////
// RFC1321 P11 �� define ����Ă��� HH()
    function MD5HH(a,b,c,d,x,s,ac){
     var ans;
     ans = (a + MD5H(b,c,d) + x + ac) % 4294967296;
     ans = MD5ROTATE_LEFT(ans,s);
     ans = (ans + b) % 4294967296;
     return ans;
    }
///////////////////////////////////////
// RFC1321 P11 �� define ����Ă��� II()
    function MD5II(a,b,c,d,x,s,ac){
     var ans;
     ans = (a + MD5I(b,c,d) + x + ac) % 4294967296;
     ans = MD5ROTATE_LEFT(ans,s);
     ans = (ans + b) % 4294967296;
     return ans;
    }
///////////////////////////////////////
// RFC1321 P11 �� MD5Update()
// inputLen �̒P�ʂ� byte
    function MD5Update(input,inputLen){
        // myIndex �̒P�ʂ� byte
     var i;
     var myIndex;
     var partLen;
        // contextCount[0] �� byte �P�ʂɕϊ�����
        // 64byte �P�ʂŗ]�肪 myIndex
     // myIndex = (MD5contextCount[0] >>> 3) & 0x3f;
     myIndex = (MD5contextCount[0] / 8) % 64;
        // bit �P�ʂɂ��Ċi�[
     // MD5contextCount[0] += inputLen <<< 3;
     MD5contextCount[0] += inputLen * 8;

     // if(MD5contextCount[0] < inputLen <<< 3){
     if(MD5contextCount[0] < inputLen * 8){
      MD5contextCount[1]++;
     }
        // 8�{(3bit �V�t�g)�����ꍇ�A
        // ��� 3bit �̃f�[�^���̂Ă���\��������
        // ���̒l���i�[
     MD5contextCount[1] += (inputLen >>> 29) & 0x07;
        // 64 �̗]��
     partLen = 64 - myIndex;
     if(partLen <= inputLen){
      MD5Memcpy(myIndex,input,0,partLen);
      MD5Transform(MD5contextState,MD5contextBuffer,0);
      for(i=partLen;i+63<inputLen;i+=64){
       MD5Transform(MD5contextState,input,i);
      }
      myIndex = 0;
     }else{
      i=0;
     }
     MD5Memcpy(myIndex,input,i,inputLen-i);
    }
///////////////////////////////////////
// RFC1321 P12 �� MD5Final()
    function MD5Final(){
     var bits;
     var myIndex;
     var padLen;
     bits = new Array(8);
     MD5Encode(bits,MD5contextCount,8);
        // 8 �Ŋ�����(bit��byte�ɂ���)64�Ŋ������]��
     // myIndex = (MD5contextCount[0] >>> 3) & 0x3f;
     myIndex = (MD5contextCount[0] / 8) % 64;
     if(myIndex < 56){
      padLen = 56 - myIndex;
     }else{
      padLen = 120 - myIndex;
     }
     MD5Update(MD5PADDING,padLen);
     MD5Update(bits,8);
     MD5Encode(MD5digest,MD5contextState,16);
    }
///////////////////////////////////////
// RFC1321 P15 �� MD5_memcpy()
// MD5contextBuffer �փR�s�[
    function MD5Memcpy(iti1,input,iti2,len){
     var i;
     for(i=0;i<len;i++){
      MD5contextBuffer[iti1+i] = input[iti2+i];
     }
    }
///////////////////////////////////////
// RFC1321 P13 �� MD5Transform()
    function MD5Transform(state,block,i){
     var a;
     var b;
     var c;
     var d;
     var x;
     var i;
     a = state[0];
     b = state[1];
     c = state[2];
     d = state[3];
     x = new Array(16);
     MD5Decode(x,block,64);
     ///////////////////////////////////////
     // Round1
     a = MD5FF(a,b,c,d,x[0],MD5Round1S[0],0xd76aa478);
     d = MD5FF(d,a,b,c,x[1],MD5Round1S[1],0xe8c7b756);
     c = MD5FF(c,d,a,b,x[2],MD5Round1S[2],0x242070db);
     b = MD5FF(b,c,d,a,x[3],MD5Round1S[3],0xc1bdceee);
     a = MD5FF(a,b,c,d,x[4],MD5Round1S[0],0xf57c0faf);
     d = MD5FF(d,a,b,c,x[5],MD5Round1S[1],0x4787c62a);
     c = MD5FF(c,d,a,b,x[6],MD5Round1S[2],0xa8304613);
     b = MD5FF(b,c,d,a,x[7],MD5Round1S[3],0xfd469501);
     a = MD5FF(a,b,c,d,x[8],MD5Round1S[0],0x698098d8);
     d = MD5FF(d,a,b,c,x[9],MD5Round1S[1],0x8b44f7af);
     c = MD5FF(c,d,a,b,x[10],MD5Round1S[2],0xffff5bb1);
     b = MD5FF(b,c,d,a,x[11],MD5Round1S[3],0x895cd7be);
     a = MD5FF(a,b,c,d,x[12],MD5Round1S[0],0x6b901122);
     d = MD5FF(d,a,b,c,x[13],MD5Round1S[1],0xfd987193);
     c = MD5FF(c,d,a,b,x[14],MD5Round1S[2],0xa679438e);
     b = MD5FF(b,c,d,a,x[15],MD5Round1S[3],0x49b40821);
     ///////////////////////////////////////
     // Round2
     a = MD5GG(a,b,c,d,x[1],MD5Round2S[0],0xf61e2562);
     d = MD5GG(d,a,b,c,x[6],MD5Round2S[1],0xc040b340);
     c = MD5GG(c,d,a,b,x[11],MD5Round2S[2],0x265e5a51);
     b = MD5GG(b,c,d,a,x[0],MD5Round2S[3],0xe9b6c7aa);
     a = MD5GG(a,b,c,d,x[5],MD5Round2S[0],0xd62f105d);
     d = MD5GG(d,a,b,c,x[10],MD5Round2S[1],0x2441453);
     c = MD5GG(c,d,a,b,x[15],MD5Round2S[2],0xd8a1e681);
     b = MD5GG(b,c,d,a,x[4],MD5Round2S[3],0xe7d3fbc8);
     a = MD5GG(a,b,c,d,x[9],MD5Round2S[0],0x21e1cde6);
     d = MD5GG(d,a,b,c,x[14],MD5Round2S[1],0xc33707d6);
     c = MD5GG(c,d,a,b,x[3],MD5Round2S[2],0xf4d50d87);
     b = MD5GG(b,c,d,a,x[8],MD5Round2S[3],0x455a14ed);
     a = MD5GG(a,b,c,d,x[13],MD5Round2S[0],0xa9e3e905);
     d = MD5GG(d,a,b,c,x[2],MD5Round2S[1],0xfcefa3f8);
     c = MD5GG(c,d,a,b,x[7],MD5Round2S[2],0x676f02d9);
     b = MD5GG(b,c,d,a,x[12],MD5Round2S[3],0x8d2a4c8a);
     ///////////////////////////////////////
     // Round3
     a = MD5HH(a,b,c,d,x[5],MD5Round3S[0],0xfffa3942);
     d = MD5HH(d,a,b,c,x[8],MD5Round3S[1],0x8771f681);
     c = MD5HH(c,d,a,b,x[11],MD5Round3S[2],0x6d9d6122);
     b = MD5HH(b,c,d,a,x[14],MD5Round3S[3],0xfde5380c);
     a = MD5HH(a,b,c,d,x[1],MD5Round3S[0],0xa4beea44);
     d = MD5HH(d,a,b,c,x[4],MD5Round3S[1],0x4bdecfa9);
     c = MD5HH(c,d,a,b,x[7],MD5Round3S[2],0xf6bb4b60);
     b = MD5HH(b,c,d,a,x[10],MD5Round3S[3],0xbebfbc70);
     a = MD5HH(a,b,c,d,x[13],MD5Round3S[0],0x289b7ec6);
     d = MD5HH(d,a,b,c,x[0],MD5Round3S[1],0xeaa127fa);
     c = MD5HH(c,d,a,b,x[3],MD5Round3S[2],0xd4ef3085);
     b = MD5HH(b,c,d,a,x[6],MD5Round3S[3],0x4881d05);
     a = MD5HH(a,b,c,d,x[9],MD5Round3S[0],0xd9d4d039);
     d = MD5HH(d,a,b,c,x[12],MD5Round3S[1],0xe6db99e5);
     c = MD5HH(c,d,a,b,x[15],MD5Round3S[2],0x1fa27cf8);
     b = MD5HH(b,c,d,a,x[2],MD5Round3S[3],0xc4ac5665);
     ///////////////////////////////////////
     // Round4
     a = MD5II(a,b,c,d,x[0],MD5Round4S[0],0xf4292244);
     d = MD5II(d,a,b,c,x[7],MD5Round4S[1],0x432aff97);
     c = MD5II(c,d,a,b,x[14],MD5Round4S[2],0xab9423a7);
     b = MD5II(b,c,d,a,x[5],MD5Round4S[3],0xfc93a039);
     a = MD5II(a,b,c,d,x[12],MD5Round4S[0],0x655b59c3);
     d = MD5II(d,a,b,c,x[3],MD5Round4S[1],0x8f0ccc92);
     c = MD5II(c,d,a,b,x[10],MD5Round4S[2],0xffeff47d);
     b = MD5II(b,c,d,a,x[1],MD5Round4S[3],0x85845dd1);
     a = MD5II(a,b,c,d,x[8],MD5Round4S[0],0x6fa87e4f);
     d = MD5II(d,a,b,c,x[15],MD5Round4S[1],0xfe2ce6e0);
     c = MD5II(c,d,a,b,x[6],MD5Round4S[2],0xa3014314);
     b = MD5II(b,c,d,a,x[13],MD5Round4S[3],0x4e0811a1);
     a = MD5II(a,b,c,d,x[4],MD5Round4S[0],0xf7537e82);
     d = MD5II(d,a,b,c,x[11],MD5Round4S[1],0xbd3af235);
     c = MD5II(c,d,a,b,x[2],MD5Round4S[2],0x2ad7d2bb);
     b = MD5II(b,c,d,a,x[9],MD5Round4S[3],0xeb86d391);
     ///////////////////////////////////////
     state[0] = (state[0] + a) % 4294967296;
     state[1] = (state[1] + b) % 4294967296;
     state[2] = (state[2] + c) % 4294967296;
     state[3] = (state[3] + d) % 4294967296;
    }
///////////////////////////////////////
// RFC1321 P15 �� Decode()
// 4�̕����R�[�h�� 32bit(4*8bit)�̐����ɂ���
// ���͔z��́A4 �̔{���ł��鎖
    function MD5Decode(output,input,len){
     var i;
     var j;
     for(i=0;4*i<len+3;i++){
      j = 4*i;
      output[i] = input[j] + (input[j+1] *256) + (input[j+2] * 65536) + (input[j+3] *16777216);
     }
    }
///////////////////////////////////////
// RFC1321 P15 �� Encode()
// 32bit ��������A4�̕����ɂ���
    function MD5Encode(output,input,len){
     var temp;
     for(i=0;4*i<len+3;i++){
      j = 4*i;
      temp = input[i];
      output[j] = temp & 0xff;
      output[j+1] = (temp >>> 8) & 0xff;
      output[j+2] = (temp >>> 16) & 0xff;
      output[j+3] = (temp >>> 24) & 0xff;
     }
    }
///////////////////////////////////////
// MD5 �̊O������A�N�Z�X�����C���^�[�t�F�C�X�E���\�b�h
// ������ MD5 �n�b�V���ɂ�����[������]���i�[����
function MD5Main(input){
     var myStr;
     var myChar;
     var len;
     var i;
     var j;
     var iti;
     var seedStr;
     var err;
     var ans;
        // MD5 �̃O���[�o���ϐ��̏�����
        // RFC1321 P11 �� MD5Init() ���\�b�h���܂�
        // MD5Update() ���o�āAMD5Final() �܂ŏ������A
        // ���ʂ𕶎���Ƀf�R�[�h���ďo�͂���
     MD5contextCount = new Array(0,0);
     MD5contextState = new Array(0x67452301,0xefcdab89,0x98badcfe,0x10325476);
     MD5contextBuffer = new Array(64);
     MD5IntInputData = new Array();
     MD5digest = new Array(16);
        // ���[�J���ϐ��̏�����
     j = 0;
                // ������𐮐�(�����R�[�h)�̔z��ɂ���
        // %nn �ɂȂ�Ȃ������̃R�[�h
        // ����ɁA33 ��������ƃR�[�h�ɂȂ�B
        // �u\�v�u`�v�� %nn �ɂȂ�̂ŁA�e�L�g�[�ȕ���(A)�Ŗ��߂Ă���
     seedStr = '' + '!"#$%&';
     seedStr = "" + seedStr + "'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ";
     seedStr = "" + seedStr + "[A]^_Aabcdefghijklmnopqrstuvwxyz{|}~";
     err = 0;
        // %nn �ɕϊ�
     myStr = escape(input);
        // ���l�̔z��֒u������
     for(i=0;i<myStr.length;i++){
      myChar = "" + myStr.charAt(i);
      if(myChar == '%'){
       myChar = "" + myStr.charAt(i+1) + myStr.charAt(i+2);
       i+=2;
       myChar = parseInt(myChar,16);
      }else{
       iti = seedStr.indexOf(myChar,0);
       if(iti < 0){
        err = 1;
       }else{
        myChar = 33 + iti;
       }
      }
      if(err == 0){
       MD5IntInputData[j] = myChar;
       j++;
      }else{
       break;
      }
     }
     if(err == 0){
        // MD5Update() �����s
      MD5Update(MD5IntInputData,MD5IntInputData.length);
        // MD5Final() �����s
      MD5Final();
        // ���ʂ𕶎���Ƀf�R�[�h
      myChar = "" + "";
      ans = "" + "";
      for(i=0;i<16;i++){
       myChar = "" + "0" + MD5digest[i].toString(16);
       myChar = myChar.substring(myChar.length-2,myChar.length);
       ans = ans + myChar;
      }
      myChar = unescape(myChar);
     }else{
        // �����ɁA�G���[����
        // %nn ���������������B%nn �ɂȂ�Ȃ�������Ń��X�g�ɂȂ����c������
      ans = "";
     }
     return ans;
}
// �����Ȃ� 32bit �r�b�g���Z
// From http://rocketeer.dip.jp/sanaki/free/javascript/freejs18.htm
// 32bit �����Ȃ��r�b�g���Z(���])
// ���͒l : 0 <= s <= 4294967295
// �߂�l : 0 <= �߂�l <= 4294967295
    function BitNot(s){
     var s1;
     var s2;
     var ans;
     s1 = s & 0xffff;
     s2 = (s >>> 16) & 0xffff;
     s1 = ~s1;
     s2 = ~s2;
     s1 = s1 & 0xffff;
     s2 = s2 & 0xffff;
     ans = BitSub(s1,s2);
     return ans;
    }
// 32bit �����Ȃ��r�b�g���Z(OR)
// ���͒l : 0 <= s <= 4294967295
// ���͒l : 0 <= t <= 4294967295
// �߂�l : 0 <= �߂�l <= 4294967295
    function BitOr(s,t){
     var s1;
     var s2;
     var t1;
     var t2;
     var ans1;
     var ans2;
     var ans;
     s1 = s & 0xffff;
     s2 = (s >>> 16) & 0xffff;
     t1 = t & 0xffff;
     t2 = (t >>> 16) & 0xffff;
     ans1 = (s1 | t1) & 0xffff;
     ans2 = (s2 | t2) & 0xffff;
     ans = BitSub(ans1,ans2);
     return ans;
    }
// 32bit �����Ȃ��r�b�g���Z(AND)
// ���͒l : 0 <= s <= 4294967295
// ���͒l : 0 <= t <= 4294967295
// �߂�l : 0 <= �߂�l <= 4294967295
    function BitAnd(s,t){
     var s1;
     var s2;
     var t1;
     var t2;
     var ans1;
     var ans2;
     var ans;
     s1 = s & 0xffff;
     s2 = (s >>> 16) & 0xffff;
     t1 = t & 0xffff;
     t2 = (t >>> 16) & 0xffff;
     ans1 = (s1 & t1) & 0xffff;
     ans2 = (s2 & t2) & 0xffff;
     ans = BitSub(ans1,ans2);
     return ans;
    }
// 32bit �����Ȃ��r�b�g���Z(XOR)
// ���͒l : 0 <= s <= 4294967295
// ���͒l : 0 <= t <= 4294967295
// �߂�l : 0 <= �߂�l <= 4294967295
function BitXor(s,t){
     var s1;
     var s2;
     var t1;
     var t2;
     var ans1;
     var ans2;
     var ans;
     s1 = s & 0xffff;
     s2 = (s >>> 16) & 0xffff;
     t1 = t & 0xffff;
     t2 = (t >>> 16) & 0xffff;
     ans1 = (s1 ^ t1) & 0xffff;
     ans2 = (s2 ^ t2) & 0xffff;
     ans = BitSub(ans1,ans2);
     return ans;
}
// 32bit �����Ȃ��r�b�g���Z�⏕
// 16bit ���ɕ������ăr�b�g���Z�����l��
// ���Ƃ�32bit �̒l�ɂȂ�悤�Ɍ���
// ���͒l : 0 <= s <= 65535
// ���͒l : 0 <= t <= 65535
// �߂�l : 0 <= �߂�l <= 4294967295
function BitSub(s,t){
    return (s + (65536 * t));
}
