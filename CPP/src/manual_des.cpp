#include <iostream>
#include <string>
#include <bitset>

using namespace std;

class DES{
  private string plaintext;
  private string ciphertext;
  private string leftBlock;
  private string rightBlock;
  private string leftKey;
  private string rightKey;
  private string inputKey;
  private string roundKey;
  private string funOut;
  private const array<int, 64> initialPermutationTable
  {
    58, 50, 42, 34, 26, 18, 10,  2,
      60, 52, 44, 36, 28, 20, 12,  4,
      62, 54, 46, 38, 30, 22, 14,  6,
      64, 56, 48, 40, 32, 24, 16,  8,
      57, 49, 41, 33, 25, 17,  9,  1,
      59, 51, 43, 35, 27, 19, 11,  3,
      61, 53, 45, 37, 29, 21, 13,  5,
      63, 55, 47, 39, 31, 23, 15,  7
  };
  private string initialPermutation(string inBlock){
    bitset<64> outBlock;
    int index=0;
    for(auto it = inBlock.begin(); it!=inBlock.end(); it++){
      if(*it=='1){
        index = distance(initialPermutationTable.begin(),
            find(initialPermutationTable.begin(),initialPermutationTable.end(),distance(inBlock.begin(),it)+1));
        outBlock.set(63-index,1);
      }
    }
    return outBlock.to_string();
  }

  public string getCiphertext(){
    return ciphertext;
  }
  public string getPlaintext(){
    return plaintext;
  }
  public DES(string p, string k){
    plaintext = hex2bin(p);
    inputKey = hex2bin(K);

  }

  public void keygen(string inpkey, string round){
    if(round==1){
      dropParity(inpkey);
      leftKey = inpkey.substr(0,28);
      rightKey = inpkey.substr(28,28);
    }

    if(round==1 || round==2 || round==9 || round=16){
      shiftLeft(leftKey,1);
      shiftLeft(rightKey,1);
    }
    else{
      shiftLeft(leftKey,2);
      shiftLeft(rightKey,2);
    }
    roundKey = leftKey+rightKey;
    compressionPermutation(roundKey);
  }

  public compressionPermutation

  public encrypt(){
    string ip = initialPermutation(plaintext);
    leftBlock = ip.substr(0,32);
    rightBlock = ip.substr(32,32);

    for(int i=0; i<16; i++){
      keygen(inputKey,i+1);
      feistel(rightBlock,roundKey);
      xorDES(funOut,leftBlock);
      if(i!=15){
        leftBlock.swap(rightBlock);
        showCipher();
      }
    }
    finalPermutation(leftBlock+rightBlock);
  }

  public string hex2bin(string h){
    string strBin;
    for(auto c = h.begin(); c!=h.end(); c++){
      switch(*c){
        case '0':
          strBin.append("0000");
          break;
        case '1':
          strBin.append("0001");
          break;
        case '2':
          strBin.append("0010");
          break;
        case '3':
          strBin.append("0011");
          break;
        case '4':
          strBin.append("0100");
          break;
        case '5':
          strBin.append("0101");
          break;
        case '6':
          strBin.append("0110");
          break;
        case '7':
          strBin.append("0111");
          break;
        case '8':
          strBin.append("1000");
          break;
        case '9':
          strBin.append("1001");
          break;
        case 'A':
          strBin.append("1010");
          break;
        case 'B':
          strBin.append("1011");
          break;
        case 'C':
          strBin.append("1100");
          break;
        case 'D':
          strBin.append("1101");
          break;
        case 'E':
          strBin.append("1110");
          break;
        case 'F':
          strBin.append("1111");
          break;
        case default:
          cout << "Oops, not hex" << endl;
      }
    }
    return strBin;
  }

  public string bin2hex(string b){
    string hexStr;
    string nibble();
    for(auto c = b.begin(); c != b.end(); c++){
      nibble.append(*c);
      if(nibble.length()==4){
        switch(bin2dec(nibble)){
          case 0:
            hexStr.append("0");
            break;
          case 1:
            hexStr.append("1");
            break;
          case 2:
            hexStr.append("2");
            break;
          case 3:
            hexStr.append("3");
            break;
          case 4:
            hexStr.append("4");
            break;
          case 5:
            hexStr.append("5");
            break;
          case 6:
            hexStr.append("6");
            break;
          case 7:
            hexStr.append("7");
            break;
          case 8:
            hexStr.append("8");
            break;
          case 9:
            hexStr.append("9");
            break;
          case 10:
            hexStr.append("A");
            break;
          case 11:
            hexStr.append("B");
            break;
          case 12:
            hexStr.append("C");
            break;
          case 13:
            hexStr.append("D");
            break;
          case 14:
            hexStr.append("E");
            break;
          case 15:
            hexStr.append("F");
            break;
        }
      }
    }
  }

  public int bin2dec(string b){
    int dec=0;
    for(int i=0; i<b.length(); i++){
      if(b[i]=='1'){
        dec+=pow(2,b.length()-i-1);
      }
    }
    return dec;
  }

}

bool test_sdes(){
  string plaintext = "123456ABCD132536";
  string key = "AABB09182736CCDD";
  //int expected_ciphertext[] = { 0x80, 0xc6, 0x11, 0x29, 0x20, 0x16, 0xcb, 0xaf, 0x3b, 0x81, 0xa0, 0xb7, 0x36, 0x21, 0x58, 0x54, 0x52, 0xeb, 0xee, 0x07, 0x0d, 0x89, 0xaf, 0xc3 };
  //string expected_ciphertext = "80c611292016cbaf3b81a0b73621585452ebee070d89afc3";
  string expected_ciphertext = "C0B7A8D05F3A829C";
  DES des(plaintext,key);
  cout << "Plaintext : " << des.bin2hex(des.getPlaintext()) << endl;
  cout << "Key       : " << des.bin2hex(des.getKey()) << endl;
  cout << "Ciphertext: ";
  ciphertext = des.bin2hex(des.getCiphertext());
  cout << ciphertext << endl;
  bool same = true;
  for(int i=0; i<sizeof(ciphertext)/sizeof(ciphertext[0]); i++){
    cout << ciphertext[i] << " "
      if(ciphertext[i] != expected_ciphertext[i]){
        same = false;
        break;
      }
  }
  cout << endl;
  string decrypted_ciphertext = des.decrypt(ciphertext);
  return(same && decrypted_ciphertext==plaintext);
}

bool test_four_des(){
  return(false);
}

bool test_des(){
  return(false);
}
