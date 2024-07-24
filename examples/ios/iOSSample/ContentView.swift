import SwiftUI
import SwiftData
import WalletKit

struct ContentView: View {
    @State var qr: String?

    var body: some View {
        VStack {
            if let qr = qr {
                Text("QR:\(qr)")
            }
            Button("Generate qr code") {
                generateQRCode()
            }
        }
    }

    func generateQRCode() {
        Task {
            let generator = QrGenerator()
            let pubKey = try SelfCustodyKeypair()
            let qr = try await generator.generateAsync(
                apiBaseUrl: "https://app.stage.orb.worldcoin.org",
                jwt: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSU0FTU0FfUEtDUzFfVjFfNV9TSEFfMjU2Iiwic2lnbmluZ0tleUlkIjoiYTRmY2NlMDktYTZjZi00ZTFmLWExZDEtMTkyODQxOGE0OGUxIiwiZW5jcnlwdGlvbktleUlkIjoiZGI2M2Q2OTMtODY1NC00NGEzLWI0ZjYtYjhlMmQ4MWIwOTJiIn0.eyJ1c2VySWQiOiJBUUlDQUhpS1hxXzJhd1JLenZMd1piX2pHRHNOV1loMWxKaFRDb3dKZG8zTTV0UG5xZ0dGWXRmZjZndENIbURFcmxTZ3J1UkdBQUFBZ3pDQmdBWUpLb1pJaHZjTkFRY0dvSE13Y1FJQkFEQnNCZ2txaGtpRzl3MEJCd0V3SGdZSllJWklBV1VEQkFFdU1CRUVESzV0Y1Q2T09vTC1yOWs0UmdJQkVJQV9IMkVYalNDd1dLdzhHV2xUOFdsdVNYNVYweTlrRk9mbHA5QWJZM2pWMkZkSWEtdnlRcEg1clNnZkN6U2FlSURncE54d2VZY0pGN1E1cm9OOE9PYVMiLCJpYXQiOjE2OTk1MjYyOTgsImV4cCI6MTY5OTYxMjY5OH0.ERaAYL0h9cNXdBIrSKW4Jq-3HHFHTOMAnBVn4gW-e3DF6hoH4zguR1KgJMcUOKt9L2Vu1XRcaqPUasE8-x6SVCoOxbEWEElhdqUm_swiXhL40KsskjPhMKdXA_admta96tQnpfdYFMxEGFerwPgyckl4lC6QIorTdPxkAQhz4QjgObrv9B05s8O30Og2QzbntgVBG96hvrF8XWfgkvFlFuTTCBY2zN1vOxxUY5ps_fe7EwMIfFn_KNAVEEmlUB6cSuHsC4TF1KEx6ES6bpP-aLBTGYQBoXICNVzjz9QjOTLQ2yTShbx4TuJURbwaVrctu2q2r2sEfDJ1MZZTH4OUQg",
                idComm: "0x0bbedd3798299b0328a4d3d4c4c9be68935b3b3cbbc63273820cc99f1047bd63",
                selfCustodyPubkey: pubKey.pkAsPem(),
                fullDataOptIn: true
            )

            self.qr = qr.qrCode
        }
    }
}
