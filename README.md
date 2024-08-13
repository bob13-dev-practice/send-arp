# send-arp

### ARP란

Address Resolution Protocol의 약자로, IP 주소를 MAC 주소로 바꿔주는 프로토콜이다.

통신할 때 IP 주소만으로는 통신이 불가능하다. 그 이유는 IP 주소가 유동적으로 변할 수 있기 때문이다. 반면, MAC 주소는 랜카드의 고유 값으로 항상 동일하게 유지된다. 따라서 MAC 주소를 통해 서로 간의 통신이 이루어진다.


### ARP 패킷 구조
![image](https://github.com/user-attachments/assets/7dda8658-d949-4d21-9afe-2b12a46b8eb7)


### ARP 동작 원리

1. sender는 target의 MAC 주소를 알기 위해 ARP Request를 브로드캐스팅한다.(target의 MAC 주소를 모르기 때문)
    
    요청 패킷에는 target이 응답할 때 필요한 sender의 IP와 MAC 주소가 포함된다.
   ![image](https://github.com/user-attachments/assets/3c1f8d52-e3e4-4b82-b0e3-9d185ee4f24d)

    
2. target은 자신의 MAC 주소를 담은 ARP Reply 패킷을 sender에게 유니캐스트로 응답한다.
    
    이때 target은 sender의 IP와 MAC 주소를 자신의 ARP 테이블에 저장한다.
    ![image](https://github.com/user-attachments/assets/6202e86a-9418-4ff3-84c4-9e5736aac895)

    

## CTF

sender와 target의 address는 다음과 같다. 이때 arp spoofing 공격을 수행하여 sender의 arp table을 변경한다.
- sender:
  - Ip: `10.3.3.106`
  - Mac: `94:76:b7:f3:09:0a`

- target:
  - Ip: `10.3.3.1`


|  | eth - sender mac(attacker mac) | eth - target mac(victim mac) | arp - sender mac(attacker mac) | arp - sender ip(router ip) | arp - target mac(victim mac) | arp - target ip(victim ip) |
| --- | --- | --- | --- | --- | --- | --- |
| request | a0:47:d7:0a:02:b4 | 94:76:b7:f3:09:0a | a0:47:d7:0a:02:b4 | 10.3.3.1 | 94:76:b7:f3:09:0a | 10.3.3.106 |

</br>
위와 같이 패킷을 구성할 경우 sender의 arp table은 다음과 같이 라우터에 대한 Mac 주소가 attacker의 Mac 주소로 변경된다.


| IP | Mac |
| --- | --- |
| 10.3.3.1(router’s ip) | a0:47:d7:0a:02:b4(attacker’s mac) |


## Reference
- https://watermelon-sugar.tistory.com/8
