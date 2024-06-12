import Flutter
import UIKit


@available(iOS 11.3, *)
public class SwiftSecureEnclavePlugin: NSObject, FlutterPlugin {
    let seCore = SECore()
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "secure_enclave", binaryMessenger: registrar.messenger())
        let instance = SwiftSecureEnclavePlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method{
        case "generateKeyPair":
            do{
                let param = call.arguments as? Dictionary<String, Any>
                let accessControlParam = AccessControlFactory(value: param!["accessControl"] as! Dictionary<String, Any>).build()
                                
                _ = try seCore.generateKeyPair(accessControlParam: accessControlParam)
                result(resultSuccess(data:true))
            } catch {
                result(resultError(error:error))
            }
            
        case "removeKey":
            do{
                let param = call.arguments as? Dictionary<String, Any>               
                let isSuccess = try seCore.removeKey()
                result(resultSuccess(data:isSuccess))
            } catch {
                result(resultError(error:error))
            }
            
        case "isKeyCreated":
            do{
                let param = call.arguments as? Dictionary<String, Any>
                let key = try seCore.isKeyCreated()
                result(resultSuccess(data:key!))
            } catch {
                result(resultSuccess(data:false))
            }
            
        case "getPublicKey":
            do{
                let param = call.arguments as? Dictionary<String, Any>
                let key = try seCore.getPublicKey()
                result(resultSuccess(data:key!))
            } catch {
                result(resultError(error:error))
            }
            
        case "encrypt" :
            do{
                let param = call.arguments as? Dictionary<String, Any>
                let message = param!["message"] as! String
                let encrypted = try seCore.encrypt(message: message)
                result(resultSuccess(data:encrypted))
            } catch {
                result(resultError(error:error))
            }
            
        case "decrypt" :
            do{
                let param = call.arguments as? Dictionary<String, Any>
                let message = param!["message"] as! FlutterStandardTypedData
                let decrypted = try seCore.decrypt(message: message.data)
                result(resultSuccess(data:decrypted))
            } catch {
                result(resultError(error:error))
            }
            
        case "sign" :
            do{
                let param = call.arguments as? Dictionary<String, Any>
                let message = param!["message"] as! FlutterStandardTypedData
                let signature = try seCore.sign(message: message.data
                )
                
                result(resultSuccess(data:signature))
            } catch {
                result(resultError(error:error))
            }
            
        case "verify" :
            do{
                let param = call.arguments as? Dictionary<String, Any>
                let signatureText = param!["signature"] as! String
                let plainText = param!["plainText"] as! String
                let signature = try seCore.verify(
                    plainText: plainText, signature: signatureText
                )
                
                result(resultSuccess(data:signature))
            } catch {
                result(resultError(error:error))
            }
       
        default:
            return
        }
        
    }
}
