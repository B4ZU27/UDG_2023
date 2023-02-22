#include<stdio.h>
#include<stdlib.h>
#include<string>
#include <iostream>
#include <math.h>
#include <bitset>

using namespace std;
int bin_to_int(unsigned long long decimal);
int bin_to_int(bitset<8> byte1,bitset<8> byte2);
int cut_n_convert(bitset<8> byte,int strt ,int stp);

void ipv4(FILE *archivo);
void ICMPv4(FILE *archivo);

int main()
{

    unsigned char palabra;
    int i;
    char ctipo[3];
    int tipo;


    FILE *archivo;

    if ((archivo = fopen("Paquetes/ethernet_ipv4_icmp_network_unreachable.bin","rb+")) == NULL)
        {
         cout<<"Error en la apertura. Es posible que el fichero no exista \n";
        }

    else{
            cout<<"\t\t\t\n ETHERNET\n\n";
            cout<<"Direccion MAC destino:\n";
            for(i=0;i<=5;i++){
                palabra = fgetc(archivo);
                printf("%02x:",palabra);
            }

            cout<<"\n";

            cout<<"Direccion MAC origen:\n";
            for(i=0;i<=5;i++){
                palabra=fgetc(archivo);
                printf ("%02x:",palabra);
            }
            cout<<"\n";

            cout<<"Tipo de codigo:\n";
            for(i=0;i<=1;i++){
                palabra=fgetc(archivo);
                printf ("%02x",palabra);
            }
            sprintf(ctipo,"%02X",palabra);
            string hex_string(ctipo);
            int decimal_int = stoi(hex_string, nullptr, 16);
            switch(decimal_int)
            {
            case 0:
                cout<<": - IPv4"<<endl;
                ipv4(archivo);
                break;
            case 6:
                cout<<": - ARP"<<endl;
                break;
            case 53:
                cout<<": - RARP";
                break;
            case 221:
                cout<<": - IPv6";
                break;
            }



            cout<<"\n";

            //switch(tipo)




            cout<<"Datos: ";
            while (!feof(archivo)){

                palabra=fgetc(archivo);
                printf ("%02x:",palabra);
            }



    }
        fclose(archivo);
        return (0);
}

void ipv4(FILE* archivo){

    int i;
    bitset<8> cpt[20];

    for(i=0;i<20;i++){
        cpt[i] = fgetc(archivo);
        //cout<<cpt[i]<<endl;
    }
    //version
    //cout<<"byte 1 = "<<cpt[0]<<endl;
    int data = cut_n_convert(cpt[0], 4, 7);
    cout<<"Version: "<<data<<endl;
    //cout<<"byte 1 = "<<cpt[0]<<endl;
    data = cut_n_convert(cpt[0],0,3);
    cout<<"Tamanio Cabecera(IHL): "<< (data*32)/8<<"bytes."<<endl;
    //cout<<"byte 2 = "<<cpt[1]<<endl;
    data = cut_n_convert(cpt[1],5,7);
    cout<<"Tipo de servicio:"<<endl;
    switch(data){
        case 0:
            cout<<"\tDe rutina";
            break;
        case 1:
            cout<<"\tPrioritario";
            break;
        case 2:
            cout<<"\tInmediato";
            break;
        case 3:
            cout<<"\tRelampago";
            break;
        case 4:
            cout<<"\tInvalidacion relampago";
            break;
        case 5:
            cout<<"\tProcesando llamada critica y de emergencia\t";
            break;
        case 6:
            cout<<"\tControl de trabajo de internet";
            break;
        case 7:
            cout<<"\tControl de red";
            break;}

    cout<<endl;

    if(cpt[1][4])
        cout<<"\tRetardo: bajo";
    else
        cout<<"\tRetardo: normal";
    cout<<endl;
    if(cpt[1][3])
        cout<<"\tRendimiento: alto";
    else
        cout<<"\tRendimiento: normal";
    cout<<endl;
    if(cpt[1][2])
        cout<<"\tFiabilidad: alta"<<endl;
    else
        cout<<"\tFiabilidad: normal"<<endl;

    //cout<<"byte 3 y 4 = "<<cpt[2]<<" "<<cpt[3]<<endl;
    cout<<"Longitud total: "<< bin_to_int(cpt[2],cpt[3]) <<"bytes "<<endl;

    //cout<<"byte 5 y 6 = "<<cpt[4]<<" "<<cpt[5]<<endl;
    bitset<16> ident(cpt[4].to_ulong() * 0x100 + cpt[5].to_ulong());
    unsigned long ident_dec = ident.to_ulong();
    cout<<"identificador: "<< ident_dec <<endl;


    if(cpt[6][6])
        cout<<"Divisible\t";
    else
        cout<<"No divisible\t";

    if(cpt[6][5])
        cout<<"Fragmento intermedio\t";
    else
        cout<<"Ultimo Fragmento\t";

    //cout<<endl<<"byte 7 y 8 = "<<cpt[6]<<" "<<cpt[7]<<endl;
    bitset<16> fragmento(cpt[6].to_ulong() * 0x100 + cpt[7].to_ulong());
    fragmento[14] = 0;
    fragmento[13] = 0;
    //cout<<fragmento<<endl;
    unsigned long fragmento_dec = fragmento.to_ulong();
    cout<<"Posicion del Fragmento: "<< fragmento_dec <<endl;

    //cout<<"byte 9 = "<<cpt[8]<<endl;
    data = bin_to_int(cpt[8].to_ullong());
    cout<<"Tiempo de vida(TTL): "<<data<<endl;

    //cout<<"byte 10 = "<<cpt[9]<<endl;
    data = bin_to_int(cpt[9].to_ullong());
    cout<<"Protocolo: ";
    switch(data){
        case 1:
            cout<<"ICMPv4: ";
            ICMPv4(archivo);
            break;
        case 6:
            cout<<"TCP\t";
            break;
        case 17:
            cout<<"UDP\t";
            break;
        case 58:
            cout<<"ICMPv6\t";
            break;
        case 118:
            cout<<"STP\t";
            break;
        case 121:
            cout<<"SMP\t";
            break;}

    //cout<<endl<<"byte 11 y 12 = "<<cpt[10]<<" "<<cpt[11]<<endl;
    cout<<endl<<"Suma de control de cabecera(CHECKSUM): "<< bin_to_int(cpt[10],cpt[11]) <<endl;

    //cout<<"byte 13,14,15,16 = "<<cpt[12]<<" "<<cpt[13]<<" "<<cpt[14]<<" "<<cpt[15]<<endl;
    int datas[20];
    for(int i=12;i<20;i++)
        datas[i]=bin_to_int(cpt[i].to_ullong());
    //cout<<" "<<datas[i];
    cout<<"Direccion IP de Origen:  "<<datas[12]<<"."<<datas[13]<<"."<<datas[14]<<"."<<datas[15]<<endl;

    //cout<<"byte 17,18,19,20 = "<<cpt[16]<<" "<<cpt[17]<<" "<<cpt[18]<<" "<<cpt[19]<<endl;
    cout<<"Direccion IP de Origen:  "<<datas[16]<<"."<<datas[17]<<"."<<datas[18]<<"."<<datas[19]<<endl;


}

void ICMPv4(FILE* archivo)
{
    int data;
    bitset<8> cpt[4];
    for(int i=0;i<4;i++)
            cpt[i] = fgetc(archivo);

        cout<<endl<<"\tTYPE: ";

        data = bin_to_int(cpt[0].to_ullong());
        switch(data){
             case 0:
                cout<<"Echo Reply (respuesta de eco)";
                break;
            case 3:
                cout<<"Destination Unreacheable(destino inaccesible)";
                break;
            case 4:
                cout<<"Source Quench(disminucion del trafico desde el origen)";
                break;
            case 5:
                cout<<"Redirect(redireccionar - cambio de ruta)";
                break;
            case 8:
                cout<<"Echo(solicitud de eco)";
                break;
            case 11:
                cout<<"Time Exceeded (tiempo excedido para un datagrama)";
                break;
            case 12:
                cout<<"Parameter Problem(problema de parametros)";
                break;
            case 13:
                cout<<"Timestamp(solicitud de marca de tiempo)";
                break;
            case 14:
                cout<<"Timestamp Reply(respuesta de marca de tiempo)";
                break;
                break;
            case 15:
                cout<<"Information Request(solicitud de informacion)";
                break;
                break;
            case 16:
                cout<<"Information Reply(respuesta de informacion)";
                break;
                break;
            case 17:
                cout<<"Adressmask(solicitud de mascara de direccion)";
                break;
                break;
            case 18:
                cout<<"Adressmask Reply(respuesta de masacara de direccion)";
                break;
            default:
                cout<<"Valio madre: "<<data<<" "<<cpt[0];
                break;
        }

        cout<<endl<<"\tCODE: ";
        data = bin_to_int(cpt[1].to_ullong());
        switch(data){
            case 0:
                cout<<"no se puede llegar a la red";
                break;
            case 1:
                cout<<"no se puede llegar al host o aplicacion de destino";
                break;
            case 2:
                cout<<"el destino no dispone del protocolo solicitado";
                break;
            case 3:
                cout<<"no se puede llegar al puerto destino o la aplicacion destino no esta libre";
                break;
            case 4:
                cout<<"se necesita fragmentacion , pero el flag correspondiente indica lo contrario";
                break;
            case 5:
                cout<<"la ruta de origen no es correcta";
                break;
            case 6:
                cout<<"no se conoce la red destino";
                break;
            case 7:
                cout<<"no se conoce el host destino";
                break;
            case 8:
                cout<<"el host origen esta aislado";
                break;
            case 9:
                cout<<"la comunicacion con la red destino esta prohibida por razones administrativas";
                break;
            case 10:
                cout<<"la comunicacion con el host destino esta prohibida por razones administrativas";
                break;
            case 11:
                cout<<"no se puede llegar a la red destino debido al tipo de servicio";
                break;
            case 12:
                cout<<"no se puede llegar a el host destino debido al tipo de servicio";
                break;
            default:
                cout<<"Valio madre: "<<data<<" "<<cpt[1];
                break;
            }
            cout<<endl<<"\tCHECKSUM: "<<bin_to_int(cpt[2],cpt[3]);
}




void ARP(FILE* archivo){
    int data;
    bitset<8> cpt[36];
    for(int i=0;i<4;i++)
            cpt[i] = fgetc(archivo);
    cout<<"Tipo de paquete: ";
    data = bin_to_int()
    switch(data)

}
int cut_n_convert(bitset<8> byte,int strt ,int stp){
    unsigned long long conversion;

        /*for(int i = 7; i >= 0;i--)
            cout<<byte[i];
        cout<<endl;*/
    if(strt == 0 && stp == 8){
        return bin_to_int(byte.to_ullong());
    }else{
        bitset<8> bsalida;
        int indice = 0;
        for(strt;stp>=strt;strt++){
            bsalida[indice] = byte[strt];
            //cout<<bsalida[indice];
            indice++;}
        //cout<<"byte salida = "<<bsalida<<endl;
        return bin_to_int(bsalida.to_ullong());
    }
}

int bin_to_int(unsigned long long decimal_v){
    int decimal = 0, base = 1;
    while (decimal_v) {
        //cout<<"iteracion-";
        int last_digit = decimal_v % 10;
        //cout<<"-l-"<<last_digit;
        decimal += last_digit * base;
        //cout<<"-dec-"<<decimal;
        base *= 2;
        decimal_v /= 10;
        //cout<<"-DecV-"<<decimal_v<<endl;
        }
    return decimal;
}

int bin_to_int(bitset<8> byte1,bitset<8> byte2){
    bitset<16> bigbyte(byte1.to_ulong() * 0x100 + byte2.to_ulong());
    unsigned long bigbyte_dec = bigbyte.to_ulong();
    return int(bigbyte_dec);
}
