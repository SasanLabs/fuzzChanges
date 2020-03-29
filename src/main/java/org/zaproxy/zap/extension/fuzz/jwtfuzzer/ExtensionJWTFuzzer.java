/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.fuzz.jwtfuzzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.messagelocations.TextHttpMessageLocationReplacerFactory;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.FuzzerHttpMessageScriptProcessorAdapterUIHandler;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.view.popup.ExtensionPopupMenuItemMessageContainer;

public class ExtensionJWTFuzzer extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    private HttpFuzzerHandler httpFuzzerHandler;
    private ScriptType scriptType;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionFuzz.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    public ExtensionJWTFuzzer() {
        super();
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("fuzz.httpfuzzer.description");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void init() {
        httpFuzzerHandler = new HttpFuzzerHandler();

        MessageLocationReplacers.getInstance()
                .addReplacer(HttpMessage.class, new TextHttpMessageLocationReplacerFactory());
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);

        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            //            scriptType =
            //                    new ScriptType(
            //                            HttpFuzzerProcessorScript.TYPE_NAME,
            //                            "fuzz.httpfuzzer.script.type.jwtfuzzerprocessor",
            //                            new ImageIcon(),
            //                            true,
            //                            true);
            //            extensionScript.registerScriptType(scriptType);

            httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                    new FuzzerHttpMessageScriptProcessorAdapterUIHandler(extensionScript));
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        extensionFuzz.addFuzzerHandler(httpFuzzerHandler);
        extensionHook
                .getHookMenu()
                .addPopupMenuItem(new JWTFuzzAttackPopupMenuItem(extensionFuzz, httpFuzzerHandler));
        extensionHook
                .getHookMenu()
                .addPopupMenuItem(
                        new ExtensionPopupMenuItemMessageContainer(
                                Constant.messages.getString("jwt.fuzz.popup.menu.item.attack")));
    }

    @Override
    public void unload() {
        super.unload();

        if (getView() != null) {
            ExtensionScript extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
            if (extensionScript != null) {
                // extensionScript.removeScripType(scriptType);
            }
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }
}
