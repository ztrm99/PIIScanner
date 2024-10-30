package com.burpextension;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.sitemap.SiteMap;

import java.util.regex.Pattern;

public class MyProxyResponseHandler implements ProxyResponseHandler
{
    private final Logging logging;
    private final Http http;
    private final SiteMap sitemap;

    public MyProxyResponseHandler(MontoyaApi api)
    {

        logging = api.logging();
        http = api.http();
        sitemap = api.siteMap();
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
//        logging.logToOutput("Initial intercepted proxy response from " + interceptedResponse.initiatingRequest().httpService());

        Annotations annotations = interceptedResponse.annotations();

        if(hasPII(interceptedResponse)){
            annotations = annotations.withNotes("Response has PII string").withHighlightColor(HighlightColor.YELLOW);

        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse,annotations);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
//        logging.logToOutput("Final intercepted proxy response from " + interceptedResponse.initiatingRequest().httpService());

        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    public static boolean hasPII (InterceptedResponse interceptedRequest) {
        String regex1 = "\\bCPF\\s*(\\d{11})\\b";
        String regex2 = "\\\\bCPF\\\\s*([0-9]{3}\\\\.[0-9]{3}\\\\.[0-9]{3}-[0-9]{2})\\\\b";
        Pattern pattern1 = Pattern.compile(regex1);
        Pattern pattern2 = Pattern.compile(regex2);
        return interceptedRequest.contains(pattern1) | interceptedRequest.contains(pattern2);
    }

}