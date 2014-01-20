/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package biz.trustpay.oauth;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import oauth.signpost.http.HttpParameters;

public class Verifier extends HttpServlet {

    final static String sharedsecret = "voiceinthecloud";

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            response.setContentType("text/html;charset=UTF-8");
            //Get the application_id paramter from the incoming query string as it is the Consumer Identifier:
            String application_id = request.getParameter("application_id");

            //Creare OAuth consumer object from the Consumer Identifier and shared secret:
            OAuthConsumer consumer = new DefaultOAuthConsumer(application_id, sharedsecret);

            //Get the authorization header with all the incoming OAuth information
            String authorization = request.getHeader("authorization");
            //Extract the signature,nonce and timestamp from the header if header exists else get from query string
            String signature_in = "";
            String oauth_nonce = "";
            String oauth_timestamp = "";
            String url_tosign = request.getRequestURL().toString() + "?" + request.getQueryString();
            if (authorization != null) {
                signature_in = getValue("oauth_signature", authorization, ",");
                oauth_nonce = getValue("oauth_nonce", authorization, ",");
                oauth_timestamp = getValue("oauth_timestamp", authorization, ",");
            } else {
                String querystring = request.getQueryString();
                if (querystring != null) {
                    signature_in = getValue("oauth_signature", querystring, "&");
                    oauth_nonce = getValue("oauth_nonce", querystring, "&");
                    oauth_timestamp = getValue("oauth_timestamp", querystring, "&");
                    //Clear all OAuth params
                    url_tosign = url_tosign.replace("&oauth_signature=" + signature_in, "");
                    url_tosign = url_tosign.replace("&oauth_consumer_key=" + application_id, "");
                    url_tosign = url_tosign.replace("&oauth_version=1.0", "");
                    url_tosign = url_tosign.replace("&oauth_signature_method=HMAC-SHA1", "");
                    url_tosign = url_tosign.replace("&oauth_nonce=" + oauth_nonce, "");
                    url_tosign = url_tosign.replace("&oauth_timestamp=" + oauth_timestamp, "");
                }
            }
            HttpParameters httpparms = new HttpParameters();
            httpparms.put("oauth_nonce", oauth_nonce);
            httpparms.put("oauth_timestamp", oauth_timestamp);
            consumer.setAdditionalParameters(httpparms);
            //Append the nonce and timestamp to incoming url and get signed url

            String signed_url = consumer.sign(url_tosign);
            //Extract verification signature from signed URl
            String test_signature = getValue("oauth_signature", signed_url, "&");

            //Compare incoming signature to extracted verification signature.
            if (signature_in.equals(test_signature)) {
                //PROCESS a succesful match ..
                //........
                //........
                //........
                System.out.println("Signatures match!");
                PrintWriter out = response.getWriter();
                try {
                    out.println("Thank you!");
                } finally {
                    out.close();
                }
            } else {
                //INVALID OAuth Signature.
                response.sendError(401, "INVALID OAUTH SIGNATURE");
            }
        } catch (OAuthMessageSignerException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OAuthExpectationFailedException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        } catch (OAuthCommunicationException ex) {
            Logger.getLogger(Verifier.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //Extract value from splitter separated value pairs
    private String getValue(String key, String querystring, String splitter) {
        String ret = "";
        if (querystring != null) {
            String[] pairs = querystring.split(splitter);
            for (int i = 0; i < pairs.length; i++) {
                String[] pair = pairs[i].split("=");
                if (pair.length == 2) {
                    //System.out.println(key + ":" + pair[0] + ";" + pair[1]);
                    if (pair[0].trim().equals(key)) {
                        ret = pair[1].replaceAll("\"", "");
                    }
                }
            }
        }
        return ret;

    }
    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
