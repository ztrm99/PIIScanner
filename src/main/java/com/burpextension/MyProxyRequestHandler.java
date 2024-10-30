package com.burpextension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;
import java.util.regex.Pattern;


public class MyProxyRequestHandler implements ProxyRequestHandler
{
    private final Logging logging;
    private final Http http;
    private final SiteMap sitemap;
    public MyProxyRequestHandler(MontoyaApi api)
    {
        logging = api.logging();
        http = api.http();
        sitemap = api.siteMap();
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
//        logging.logToOutput("Initial intercepted proxy request to " + interceptedRequest.httpService());
        Annotations annotations = interceptedRequest.annotations();
        HttpRequestResponse getResponse = http.sendRequest(interceptedRequest);
        if(hasPII(interceptedRequest) | hasPII(getResponse)){
            annotations = annotations.withNotes("PII string detected").withHighlightColor(HighlightColor.YELLOW);
            logging.logToOutput("ISSUE PII Found");
            sitemap.add(
                    AuditIssue.auditIssue("ISSUE PII Found",
                            "Testing Detail",
                            "Test Remediation" ,
                            interceptedRequest.url(),
                            AuditIssueSeverity.HIGH,
                            AuditIssueConfidence.CERTAIN,
                            "Test Background",
                            "Test Remediation background",
                            AuditIssueSeverity.HIGH,
                            getResponse)
            );
        }

        return ProxyRequestReceivedAction.continueWith(interceptedRequest,annotations);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    public static boolean hasPII (InterceptedRequest interceptedRequest) {
        String regex1 = "\\bCPF\\s*(\\d{11})\\b";
        String regex2 = "\\\\bCPF\\\\s*([0-9]{3}\\\\.[0-9]{3}\\\\.[0-9]{3}-[0-9]{2})\\\\b";
        Pattern pattern1 = Pattern.compile(regex1);
        Pattern pattern2 = Pattern.compile(regex2);
        return interceptedRequest.contains(pattern1) | interceptedRequest.contains(pattern2);
    }

    public static boolean hasPII (HttpRequestResponse interceptedResponse) {
        String regex1 = "\\bCPF\\s*(\\d{11})\\b";
        String regex2 = "\\\\bCPF\\\\s*([0-9]{3}\\\\.[0-9]{3}\\\\.[0-9]{3}-[0-9]{2})\\\\b";
        Pattern pattern1 = Pattern.compile(regex1);
        Pattern pattern2 = Pattern.compile(regex2);
        return interceptedResponse.contains(pattern1) | interceptedResponse.contains(pattern2);
    }
}